// selfexttool_test.go — proves dispatch_selfext (mallcoppro-0d95) is
// advertised to the model and dial-gates its commit against a REAL
// git-backed store: propose-only ("non") writes nothing, an "auto" dial
// ("semi"/"fully") commits a durable store.SelfextDispatchRecord.
package investigate

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
)

// TestToolDefs_IncludesDispatchSelfext proves dispatch_selfext is actually
// advertised to the model, with its three required fields present.
func TestToolDefs_IncludesDispatchSelfext(t *testing.T) {
	defs := ToolDefs()
	var found map[string]any
	for _, d := range defs {
		if d.Name == "dispatch_selfext" {
			schema, ok := d.InputSchema.(map[string]any)
			if !ok {
				t.Fatalf("dispatch_selfext InputSchema is not a map[string]any: %T", d.InputSchema)
			}
			found, _ = schema["properties"].(map[string]any)
			req, _ := schema["required"].([]string)
			if len(req) != 3 {
				t.Errorf("dispatch_selfext required = %v, want 3 entries (lane, detector_id, event_type)", req)
			}
		}
	}
	if found == nil {
		t.Fatalf("ToolDefs() missing dispatch_selfext; got %v", toolNames(defs))
	}
	for _, key := range []string{"lane", "detector_id", "event_type", "target_family", "severity", "actor", "source", "reason"} {
		if _, ok := found[key]; !ok {
			t.Errorf("dispatch_selfext InputSchema.properties missing %q", key)
		}
	}
	// The autonomy dial must NEVER be a model-suppliable input field -- the
	// model cannot raise its own blast radius by asserting a dial position.
	if _, ok := found["autonomy"]; ok {
		t.Error("dispatch_selfext InputSchema.properties has an \"autonomy\" field -- the dial must be read from mallcop.yaml, never accepted from the model")
	}
}

// dispatchInput is the standard well-formed tool_use input used across the
// enforcement tests below.
func dispatchInput() map[string]any {
	return map[string]any{
		"lane":        "heal",
		"detector_id": "authored-deploy-burst",
		"event_type":  "github.deployment",
		"severity":    "high",
		"actor":       "svc-deploy",
		"source":      "github",
		"reason":      "operator asked to cover deploy-burst gap",
	}
}

// TestDispatchSelfext_ProposeOnly_DoesNotCommit is the propose-only ("non",
// the default) enforcement case: the tool returns a proposal and the REAL
// git-backed store's selfext_dispatches stream stays empty.
func TestDispatchSelfext_ProposeOnly_DoesNotCommit(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomyNon, false)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	res, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "dispatch_selfext", dispatchInput())
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out, ok := res.(SelfextDispatchOutput)
	if !ok {
		t.Fatalf("result type = %T, want SelfextDispatchOutput", res)
	}
	if out.Committed {
		t.Fatalf("propose-only dispatch reported Committed=true -- dial gate breached; got %+v", out)
	}
	if !out.Proposed {
		t.Fatalf("propose-only dispatch did not set Proposed; got %+v", out)
	}
	if out.Autonomy != config.AutonomyNon {
		t.Errorf("out.Autonomy = %q, want %q", out.Autonomy, config.AutonomyNon)
	}

	// Ground truth: the REAL store has nothing on the selfext_dispatches
	// stream.
	got, err := st.LoadSelfextDispatches()
	if err != nil {
		t.Fatalf("LoadSelfextDispatches: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("selfext_dispatches stream has %d record(s) after a propose-only dispatch, want 0: %+v", len(got), got)
	}
}

// TestDispatchSelfext_AutoDial_Commits proves BOTH "semi" and "fully" reads
// commit a durable record through the real store.Append seam -- ground
// truth read back via LoadSelfextDispatches, not just the tool's own return
// value.
func TestDispatchSelfext_AutoDial_Commits(t *testing.T) {
	for _, dial := range []string{config.AutonomySemi, config.AutonomyFully} {
		t.Run(dial, func(t *testing.T) {
			dir := initRepo(t)
			writeConfigAt(t, dir, dial, false)
			st, err := store.Open(dir)
			if err != nil {
				t.Fatalf("store.Open: %v", err)
			}

			res, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "dispatch_selfext", dispatchInput())
			if err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}
			out, ok := res.(SelfextDispatchOutput)
			if !ok {
				t.Fatalf("result type = %T, want SelfextDispatchOutput", res)
			}
			if !out.Committed || out.Proposed {
				t.Fatalf("auto-dial (%s) dispatch not committed; got %+v", dial, out)
			}
			if out.Autonomy != dial {
				t.Errorf("out.Autonomy = %q, want %q", out.Autonomy, dial)
			}

			// Ground truth: the REAL store has exactly one committed record,
			// with the fields carried through and the dial that authorized it.
			got, err := st.LoadSelfextDispatches()
			if err != nil {
				t.Fatalf("LoadSelfextDispatches: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("selfext_dispatches stream has %d record(s), want 1: %+v", len(got), got)
			}
			rec := got[0]
			if rec.Lane != "heal" || rec.DetectorID != "authored-deploy-burst" || rec.EventType != "github.deployment" {
				t.Errorf("committed record = %+v, want lane=heal detector_id=authored-deploy-burst event_type=github.deployment", rec)
			}
			if rec.Severity != "high" || rec.Actor != "svc-deploy" || rec.Source != "github" {
				t.Errorf("committed record = %+v, want severity=high actor=svc-deploy source=github", rec)
			}
			if rec.Autonomy != dial {
				t.Errorf("committed record autonomy = %q, want %q", rec.Autonomy, dial)
			}
			if rec.RequestedAt.IsZero() {
				t.Error("committed record RequestedAt is zero")
			}
		})
	}
}

// TestDispatchSelfext_DefaultSeverity proves an omitted severity defaults to
// "medium" on the committed record, mirroring the CLI's own --severity
// default.
func TestDispatchSelfext_DefaultSeverity(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomyFully, false)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	in := dispatchInput()
	delete(in, "severity")
	if _, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "dispatch_selfext", in); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	got, err := st.LoadSelfextDispatches()
	if err != nil {
		t.Fatalf("LoadSelfextDispatches: %v", err)
	}
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("committed record severity = %+v, want exactly one record with severity=medium", got)
	}
}

// TestDispatchSelfext_MissingRequiredField_Errored proves each of the three
// required fields is actually enforced, and that a rejected call commits
// nothing.
func TestDispatchSelfext_MissingRequiredField_Errored(t *testing.T) {
	for _, missing := range []string{"lane", "detector_id", "event_type"} {
		t.Run(missing, func(t *testing.T) {
			dir := initRepo(t)
			writeConfigAt(t, dir, config.AutonomyFully, false)
			st, err := store.Open(dir)
			if err != nil {
				t.Fatalf("store.Open: %v", err)
			}
			in := dispatchInput()
			delete(in, missing)

			if _, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "dispatch_selfext", in); err == nil {
				t.Fatalf("expected an error with %q missing", missing)
			}
			got, err := st.LoadSelfextDispatches()
			if err != nil {
				t.Fatalf("LoadSelfextDispatches: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("a rejected dispatch (missing %q) still committed %d record(s)", missing, len(got))
			}
		})
	}
}
