package pipeline_test

// consumer_suppress_case_pipeline_test.go is the mallcoppro-419 FEATURE-level
// proof: a 'suppress-case' directive, persisted to a REAL git-backed store,
// drops exactly the case the operator was shown on the NEXT real
// pipeline.Run — and a SIBLING case sharing type/actor but differing only by
// entity is NOT suppressed and still fires. Nothing pre-existing exercised
// this shape: every other directive fixture in this package targets a
// SINGLE finding/actor, never two findings that differ ONLY by the entity
// buried in Evidence.
//
// The fixture: two repo.add_collaborator events from the SAME actor
// ("admin-user"), granting access to two DIFFERENT external principals
// ("alice-ext" and "bob-ext"). core/detect/new_external_access.go emits one
// finding per event, both Type="new-external-access" Actor="admin-user" —
// identical source/type/actor triple, so the PRE-EXISTING 'suppress' op
// (matchPattern's segment-glob) cannot tell them apart at all: suppressing
// one via the console's derived Pattern would suppress both. They differ
// ONLY in Evidence.grantee ("alice-ext" vs "bob-ext"), which core/cases
// clusters as a DIFFERENT case per core/cases/collapse_test.go's
// TestCollapse_DistinctEntity_DistinctCases. A 'suppress-case' directive
// naming alice's case ID must drop ONLY alice's finding.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// adminKnownBaseline pins "admin-user" as a known actor so core/detect's
// new-actor detector stays quiet, isolating the fixture to the ONE detector
// (new-external-access) this test deliberately exercises — the finding count
// this test asserts on must come from exactly that detector, nothing else.
func adminKnownBaseline() *baseline.Baseline {
	return &baseline.Baseline{KnownActors: []string{"admin-user"}}
}

// twoEntityGrantEvents returns two repo.add_collaborator events from the SAME
// actor, granting access to two DIFFERENT external principals — the fixture
// shape core/cases/collapse_test.go's TestCollapse_DistinctEntity_DistinctCases
// proves clusters as two distinct cases (same type+actor, different entity).
// Neither event carries an approval-signal key, so
// core/detect/new_external_access.go's hasApprovalSignal gate does not
// suppress either at the detector floor.
func twoEntityGrantEvents() []event.Event {
	ts := time.Date(2026, 6, 18, 14, 22, 0, 0, time.UTC)
	alicePayload, _ := json.Marshal(map[string]string{
		"action":       "add_collaborator",
		"collaborator": "alice-ext",
		"permission":   "write",
	})
	bobPayload, _ := json.Marshal(map[string]string{
		"action":       "add_collaborator",
		"collaborator": "bob-ext",
		"permission":   "write",
	})
	return []event.Event{
		{ID: "evt-grant-alice", Source: "github", Type: "repo.add_collaborator", Actor: "admin-user", Timestamp: ts, Org: "atom", Payload: alicePayload},
		{ID: "evt-grant-bob", Source: "github", Type: "repo.add_collaborator", Actor: "admin-user", Timestamp: ts.Add(time.Minute), Org: "atom", Payload: bobPayload},
	}
}

// suppressCaseDirective builds a 'suppress-case' Directive naming caseID —
// exactly the shape mallcop-pro's emitter (mallcoppro-4c9, a separate item)
// will write once a customer's pinned MALLCOP_VERSION supports this op.
func suppressCaseDirective(caseID string) store.Directive {
	return store.Directive{Op: "suppress-case", Pattern: caseID, Reason: "operator dismissed the alice-ext grant case"}
}

// storedFindingIDs replays the store's KindFindings stream and returns the
// set of persisted finding IDs — what the NEXT scan (and any console reading
// findings.json) actually sees survived.
func storedFindingIDs(t *testing.T, st *store.Store) map[string]bool {
	t.Helper()
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		t.Fatalf("load stored findings: %v", err)
	}
	out := make(map[string]bool, len(raws))
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("unmarshal stored finding: %v", err)
		}
		out[f.ID] = true
	}
	return out
}

// TestPipeline_SuppressCase_DropsNamedCase_SiblingEntityCaseStillFires is the
// headline mallcoppro-419 acceptance proof, through the REAL pipeline against
// a REAL git-backed store.
func TestPipeline_SuppressCase_DropsNamedCase_SiblingEntityCaseStillFires(t *testing.T) {
	root := useShippedCorpus(t)

	be := cleanResolveBackend(t)
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	st := newGitStore(t)

	// The case ID a console/CLI would have shown the operator for the
	// alice-ext grant — computed the SAME way pipeline.go's escalation loop
	// and core/cases.Collapse do (core/cases.CaseID), never guessed.
	aliceCaseID := cases.CaseID(cases.Key{Type: "new-external-access", Actor: "admin-user", Entity: "alice-ext"})
	bobCaseID := cases.CaseID(cases.Key{Type: "new-external-access", Actor: "admin-user", Entity: "bob-ext"})
	if aliceCaseID == bobCaseID {
		t.Fatalf("fixture invalid: alice-ext and bob-ext must hash to DIFFERENT case IDs, both got %q", aliceCaseID)
	}

	// Persist the suppress-case directive BEFORE the scan runs — proving the
	// directive, once written by an operator, is honored by the NEXT scan
	// that opens this store (the append-only, first-class contract every
	// other directive in this package already proves).
	if _, err := st.Append(store.KindDirectives, suppressCaseDirective(aliceCaseID)); err != nil {
		t.Fatalf("append suppress-case directive: %v", err)
	}

	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, twoEntityGrantEvents())),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		Baseline:  adminKnownBaseline(),
		Cascade:   agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "no additional tool evidence gathered", toolCalls: 6, distinctTools: 4}},
		Workers:   1,
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	// THE ACCEPTANCE ASSERTION: exactly one finding survives — bob-ext's.
	// alice-ext's case was named by the directive and is gone; bob-ext's
	// sibling case, sharing type+actor but a DIFFERENT entity, was NOT named
	// and still fires. This is explicitly the point, not incidental.
	if sum.FindingsDetected != 1 {
		t.Fatalf("FindingsDetected = %d, want exactly 1 (alice-ext's case suppressed, bob-ext's sibling case must still fire); summary=%+v", sum.FindingsDetected, sum)
	}
	if sum.Resolved+sum.Escalated != sum.FindingsDetected {
		t.Errorf("invariant broken: Resolved(%d)+Escalated(%d) != FindingsDetected(%d)", sum.Resolved, sum.Escalated, sum.FindingsDetected)
	}

	kept := storedFindingIDs(t, st)
	if len(kept) != 1 {
		t.Fatalf("store holds %d findings, want exactly 1: %v", len(kept), kept)
	}
	if kept["finding-evt-grant-alice"] {
		t.Errorf("alice-ext's finding (finding-evt-grant-alice) was stored — its suppress-case directive should have dropped it before it ever reached the store")
	}
	if !kept["finding-evt-grant-bob"] {
		t.Errorf("bob-ext's finding (finding-evt-grant-bob) was NOT stored — the sibling case (same type/actor, different entity) must still fire; got stored=%v", kept)
	}

	// APPEND-ONLY: the directive we wrote must still be exactly what we
	// wrote — pipeline.Run consumes the directives stream read-only, it
	// never rewrites or clears it.
	dirs, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("directives stream holds %d records, want exactly the 1 we appended: %+v", len(dirs), dirs)
	}
	if dirs[0].Op != "suppress-case" || dirs[0].Pattern != aliceCaseID {
		t.Errorf("stored directive = %+v, want Op=suppress-case Pattern=%q (unchanged from what was appended)", dirs[0], aliceCaseID)
	}
}

// TestPipeline_SuppressCase_NoDirective_BothCasesFire is the control: over
// the IDENTICAL fixture with NO suppress-case directive, both cases fire.
// Without this, a bug that suppressed EVERYTHING (rather than just the named
// case) could pass the headline test vacuously if bob's finding also
// happened to be dropped by some unrelated defect.
func TestPipeline_SuppressCase_NoDirective_BothCasesFire(t *testing.T) {
	root := useShippedCorpus(t)

	be := cleanResolveBackend(t)
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	st := newGitStore(t)
	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, twoEntityGrantEvents())),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		Baseline:  adminKnownBaseline(),
		Cascade:   agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "no additional tool evidence gathered", toolCalls: 6, distinctTools: 4}},
		Workers:   1,
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if sum.FindingsDetected != 2 {
		t.Fatalf("FindingsDetected = %d, want 2 (no suppress-case directive present; both grant cases must fire)", sum.FindingsDetected)
	}
	kept := storedFindingIDs(t, st)
	if !kept["finding-evt-grant-alice"] || !kept["finding-evt-grant-bob"] {
		t.Fatalf("stored findings = %v, want both finding-evt-grant-alice and finding-evt-grant-bob", kept)
	}
}
