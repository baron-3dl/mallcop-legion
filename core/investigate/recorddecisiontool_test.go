package investigate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// seedRecordDecisionFinding opens (or inits) a git-backed store at dir and
// appends one finding, returning the opened store — the fixture record_decision
// resolves finding_id against.
func seedRecordDecisionFinding(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	f := finding.Finding{
		ID:        "finding-rd1",
		Source:    "detector:secrets-exposure",
		Type:      "secrets-exposure",
		Actor:     "alice",
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Reason:    "github pat in payload",
	}
	if _, err := st.Append(store.KindFindings, f); err != nil {
		t.Fatalf("append finding: %v", err)
	}
	return st
}

// TestToolDefs_IncludesRecordDecision proves record_decision is actually
// advertised to the model.
func TestToolDefs_IncludesRecordDecision(t *testing.T) {
	found := false
	for _, n := range toolNames(ToolDefs()) {
		if n == "record_decision" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ToolDefs() missing record_decision")
	}
}

// TestRecordDecision_ProposeOnly_DoesNotCommit is the item's enforcement test
// (a): at the propose-only autonomy dial, record_decision writes NOTHING to
// the directive stream and instead returns a proposed directive.
func TestRecordDecision_ProposeOnly_DoesNotCommit(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomyNon, false)
	st := seedRecordDecisionFinding(t, dir)

	res, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "record_decision", map[string]any{
		"op":         "suppress",
		"finding_id": "finding-rd1",
		"reason":     "known-good automation",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out, ok := res.(RecordDecisionOutput)
	if !ok {
		t.Fatalf("result type = %T, want RecordDecisionOutput", res)
	}
	if out.Applied {
		t.Fatalf("propose-only dial reported Applied=true — nothing should have committed")
	}
	if out.Proposed == nil {
		t.Fatalf("propose-only dial did not return a Proposed directive; got %+v", out)
	}

	// Ground truth: no directive was appended to the REAL store.
	raws, err := st.Load(store.KindDirectives)
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(raws) != 0 {
		t.Fatalf("directives stream has %d record(s) after a propose-only call, want 0", len(raws))
	}
}

// TestRecordDecision_AutoDial_AppendsRealDirective is the item's enforcement
// test (b): at an auto dial (fully), record_decision appends a REAL directive
// to the real git-backed store.
func TestRecordDecision_AutoDial_AppendsRealDirective(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomyFully, false)
	st := seedRecordDecisionFinding(t, dir)

	res, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "record_decision", map[string]any{
		"op":         "suppress",
		"finding_id": "finding-rd1",
		"reason":     "known-good automation",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out, ok := res.(RecordDecisionOutput)
	if !ok {
		t.Fatalf("result type = %T, want RecordDecisionOutput", res)
	}
	if !out.Applied {
		t.Fatalf("auto dial reported Applied=false; got %+v", out)
	}
	if out.Pattern != "detector:secrets-exposure/secrets-exposure/alice" {
		t.Fatalf("Pattern = %q, want the derived source/type/actor key", out.Pattern)
	}

	// Ground truth: re-open a FRESH store handle on the same on-disk repo and
	// confirm the directive really landed there (not just in-memory).
	st2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	raws, err := st2.Load(store.KindDirectives)
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("directives stream has %d record(s) after an auto-dial commit, want 1", len(raws))
	}
	var d store.Directive
	if err := json.Unmarshal(raws[0], &d); err != nil {
		t.Fatalf("decode directive: %v", err)
	}
	if d.Op != "suppress" || d.Pattern != "detector:secrets-exposure/secrets-exposure/alice" {
		t.Fatalf("directive = %+v, want op=suppress pattern=detector:secrets-exposure/secrets-exposure/alice", d)
	}
}

// TestRecordDecision_UnknownOp_Rejected proves an op outside the documented
// vocabulary is refused rather than silently written.
func TestRecordDecision_UnknownOp_Rejected(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomyFully, false)
	st := seedRecordDecisionFinding(t, dir)

	_, err := ExecuteTool(Options{Store: st, RepoRoot: dir}, "record_decision", map[string]any{
		"op":         "force-escalate",
		"finding_id": "finding-rd1",
		"reason":     "x",
	})
	if err == nil {
		t.Fatalf("record_decision accepted an unknown op; want an error")
	}
}
