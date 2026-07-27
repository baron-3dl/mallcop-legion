package detect

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestContainsElevatedKeyword covers the substring match that lets priv-escalation
// recognize cloud-specific privileged role formats, not just the bare
// "owner"/"admin" GitHub/Azure form. Regression guard for mallcoppro-9dd: the old
// exact map lookup silently missed GCP "roles/owner" and Okta "Super Admin".
func TestContainsElevatedKeyword(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"owner", true},                 // Azure / GitHub bare form (exact, still works)
		{"admin", true},                 //
		{"roles/owner", true},           // GCP — missed by the old exact match
		{"roles/editor", true},          // GCP primitive: broad write (GAP-1)
		{"Super Admin", true},           // Okta — missed by old exact match (case-insensitive)
		{"Org Administrator", true},     // contains "admin"
		{"Sites.FullControl.All", true}, // M365 Graph app role (GAP-2)
		{"write", true},                 // a write grant is elevated
		{"viewer", false},
		{"readonly", false},
		{"roles/viewer", false},
		{"", false},
	}
	tuning := defaultPrivEscalationTuning()
	for _, c := range cases {
		if got := containsElevatedKeyword(c.role, tuning); got != c.want {
			t.Errorf("containsElevatedKeyword(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

// TestPrivEscalationFiresOnCloudRoles proves the detector FIRES and marks critical
// on GCP- and Okta-format privileged role grants, exercised through the real
// Detect path. Before the substring fix these produced no priv-escalation finding
// even though the connector emitted the correct role_assignment Type + payload.
func TestPrivEscalationFiresOnCloudRoles(t *testing.T) {
	cases := []struct {
		name, source, actor, role, wantSev string
	}{
		{"gcp-roles-owner", "gcp", "deployer", "roles/owner", "critical"},
		{"okta-super-admin", "okta", "rogue", "Super Admin", "critical"},
		{"gcp-roles-editor", "gcp", "deployer2", "roles/editor", "high"},       // GAP-1: broad write, not owner/admin → high
		{"m365-fullcontrol", "m365", "appsp", "Sites.FullControl.All", "high"}, // GAP-2
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bl := &baseline.Baseline{
				KnownActors: []string{c.actor}, // suppress new-actor so we isolate priv-escalation
				ActorRoles:  map[string][]string{c.actor: {"viewer"}},
			}
			ev := event.Event{
				ID: "pe-" + c.name, Source: c.source, Type: "role_assignment",
				Actor: c.actor, Timestamp: ts(16, 8),
				Payload: raw(t, map[string]string{
					"role_name":   c.role,
					"target_user": "victim",
				}),
			}
			found := false
			var sev string
			for _, f := range Detect([]event.Event{ev}, bl) {
				if f.Type == "priv-escalation" {
					found, sev = true, f.Severity
				}
			}
			if !found {
				t.Fatalf("priv-escalation did NOT fire on %s role %q", c.source, c.role)
			}
			if sev != c.wantSev {
				t.Errorf("priv-escalation severity = %q, want %q (role %q)", sev, c.wantSev, c.role)
			}
		})
	}
}

// TestPrivEscalationOnNIP86Allowlist proves the relay's NIP-86 write-allowlist
// change reaches priv-escalation with the shape the loganalytics connector now
// emits (mallcoppro-956), exercised through the real Detect path. The connector
// GRANT (allowpubkey) maps to role_assignment with role "relay-write-allowlist"
// (carries the "write" elevated token) so priv-escalation casts its committee
// vote; the REVOKE (banpubkey) maps to action "remove_role_assignment" so the
// narrowing guard drops it. Before the fix the connector set role to the raw
// method name ("allowpubkey"), which matched no elevated keyword, so
// priv-escalation never voted for a genuine write-allowlist grant.
func TestPrivEscalationOnNIP86Allowlist(t *testing.T) {
	fires := func(action, roleName string) bool {
		bl := &baseline.Baseline{
			KnownActors: []string{"relay-admin"}, // isolate priv-escalation from new-actor
			ActorRoles:  map[string][]string{"relay-admin": {"viewer"}},
		}
		ev := event.Event{
			ID: "nip86-" + roleName, Source: "loganalytics", Type: "role_assignment",
			Actor: "relay-admin", Timestamp: ts(16, 30),
			Payload: raw(t, map[string]string{
				"action":      action,
				"role":        "relay-write-allowlist",
				"role_name":   roleName,
				"target_user": "attacker-pubkey",
			}),
		}
		for _, f := range Detect([]event.Event{ev}, bl) {
			if f.Type == "priv-escalation" {
				return true
			}
		}
		return false
	}

	if !fires("role_assignment", "allowpubkey") {
		t.Error("priv-escalation did NOT fire on NIP-86 allowpubkey GRANT (write-allowlist elevation)")
	}
	if fires("remove_role_assignment", "banpubkey") {
		t.Error("priv-escalation fired on NIP-86 banpubkey REVOKE — a revoke narrows, it does not elevate")
	}
}

// TestPrivEscalationGateIsTargetAware proves the baseline gate + in-scan dedup
// key is (actor, role, target) — not (actor, role) alone (mallcoppro-9af, ruled
// by Baron 2026-07-15). Before this fix, once (actor, role) was baselined, that
// actor granting the SAME role to ANY NEW principal was silently suppressed
// forever: a compromised known admin re-granting privileges to a fresh attacker
// principal never re-fired. This pins the three load-bearing behaviors the
// ruling requires:
//   - the SAME grant (actor, role, target) stays idempotent across a re-scan,
//   - the SAME role granted to a NEW target re-fires,
//   - a DIFFERENT role granted to the SAME target re-fires.
func TestPrivEscalationGateIsTargetAware(t *testing.T) {
	grant := func(id, actor, role, target string) event.Event {
		return event.Event{
			ID: id, Source: "github", Type: "role_assignment",
			Actor: actor, Timestamp: ts(17, 0),
			Payload: raw(t, map[string]string{
				"role_name":   role,
				"target_user": target,
			}),
		}
	}
	fires := func(bl *baseline.Baseline, ev event.Event) bool {
		for _, f := range Detect([]event.Event{ev}, bl) {
			if f.Type == "priv-escalation" {
				return true
			}
		}
		return false
	}

	t.Run("same actor+role+target is idempotent across re-scan", func(t *testing.T) {
		bl := &baseline.Baseline{
			KnownActors: []string{"admin-user"},
			ActorRoles:  map[string][]string{"admin-user": {"admin:victim"}},
		}
		ev := grant("g1", "admin-user", "admin", "victim")
		if fires(bl, ev) {
			t.Errorf("re-scan of the SAME (actor, role, target) re-fired — the gate must be idempotent for a repeated grant")
		}
	})

	t.Run("same actor+role to a NEW target re-fires", func(t *testing.T) {
		bl := &baseline.Baseline{
			KnownActors: []string{"admin-user"},
			ActorRoles:  map[string][]string{"admin-user": {"admin:victim"}},
		}
		ev := grant("g2", "admin-user", "admin", "attacker")
		if !fires(bl, ev) {
			t.Errorf("granting the SAME role to a NEW target did not fire — a compromised known admin re-granting to a fresh principal must always surface")
		}
	})

	t.Run("different role, same actor+target re-fires", func(t *testing.T) {
		bl := &baseline.Baseline{
			KnownActors: []string{"admin-user"},
			ActorRoles:  map[string][]string{"admin-user": {"contributor:victim"}},
		}
		ev := grant("g3", "admin-user", "admin", "victim")
		if !fires(bl, ev) {
			t.Errorf("granting a DIFFERENT role to the same known target did not fire")
		}
	})

	t.Run("in-scan dedup within one Detect call is also target-aware", func(t *testing.T) {
		bl := &baseline.Baseline{KnownActors: []string{"admin-user"}}
		events := []event.Event{
			grant("g4", "admin-user", "admin", "victim"),
			grant("g5", "admin-user", "admin", "victim"),   // repeat, same triple → deduped
			grant("g6", "admin-user", "admin", "attacker"), // new target → distinct finding
		}
		var privCount int
		for _, f := range Detect(events, bl) {
			if f.Type == "priv-escalation" {
				privCount++
			}
		}
		if privCount != 2 {
			t.Errorf("Detect emitted %d priv-escalation findings, want 2 (victim once, attacker once; the repeat g5 must dedup against g4)", privCount)
		}
	})
}
