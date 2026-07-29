package pipeline_test

// severity_override_verdict_invariance_test.go — the R9 regression test for
// mallcoppro-e38: an operator "severity" directive (Gap C,
// core/pipeline/consumer_attention.go) must relabel a finding's DISPLAYED
// severity without ever feeding back into core/agent's committee
// escalate/quiet vote.
//
// THE BUG this guards against: pipeline.Run used to call
// DirectiveDispatcher.ApplySeverityOverrides and reassign the result back onto
// the SAME `findings` slice that resolveAll (the committee) consumes. Since
// core/agent/triagerisk.go's triageResolveMustEscalate reads finding.Severity
// directly — "high"/"critical" forces a clean triage resolve to hand off to
// investigate instead of terminating — an operator relabeling a LOW-severity
// finding "critical" silently forced it through an extra committee tier it
// would never have seen without the directive. That is exactly the R9
// violation (consensus/cascade, not an operator-authored rule) and it
// contradicted ApplySeverityOverrides' own doc comment.
//
// THE PROOF: run the SAME real pipeline.Run() twice over the IDENTICAL fixture
// — once with no directives, once with a "severity critical" directive on the
// one finding the fixture produces (whose real detector severity is "low", a
// severity triageResolveMustEscalate does NOT treat as risky) — and assert:
//
//   - the committee's disposition (Resolved/Escalated) and the model call count
//     are IDENTICAL between the two runs (the operator's relabel changed
//     nothing about how the finding was resolved);
//   - the persisted finding record's Severity DOES differ ("low" with no
//     directive vs "critical" with the directive) — proving the override still
//     does its job, just as a display/output annotation, never as resolve
//     input.
//
// Under the pre-fix code this test fails on the call-count assertion: the
// directive run makes 2 model calls (triage forced to hand off + investigate)
// where the no-directive run makes 1 (clean triage terminal resolve).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// unusualLoginBaseline pins "alice-known" as a known actor with a login
// profile (known IP 1.1.1.1, known geo "US") but NOT the fixture login's IP —
// this drives core/detect's unusual-login detector down the "known user, new
// IP, known geo" branch, which emits a LOW-severity finding (unusual_login.go)
// carrying no malicious-shaped marker in its Type/Reason. Low severity + no
// marker means core/agent/triagerisk.go's triageResolveMustEscalate returns
// false on the UN-overridden finding — exactly the "would cleanly resolve at
// triage" precondition this test needs to detect a severity-override leak.
func unusualLoginBaseline() *baseline.Baseline {
	return &baseline.Baseline{
		KnownActors: []string{"alice-known"},
		KnownUsers: map[string]baseline.UserProfile{
			"alice-known": {KnownIPs: []string{"1.1.1.1"}, KnownGeos: []string{"US"}},
		},
	}
}

// lowSeverityLoginEvent returns a single login event for a known actor from an
// unrecognized IP but a recognized geo — the "low severity" unusual-login
// branch.
func lowSeverityLoginEvent() event.Event {
	payload, _ := json.Marshal(map[string]string{"ip": "9.9.9.9", "geo": "US"})
	return event.Event{
		ID:        "evt-login-001",
		Source:    "aws",
		Type:      "login",
		Actor:     "alice-known",
		Timestamp: time.Date(2026, 6, 18, 14, 22, 0, 0, time.UTC),
		Org:       "atom",
		Payload:   payload,
	}
}

// cleanResolveBackend always returns a high-confidence, positive-evidence
// resolve with NO evidence-pattern citations (no dates/times/baseline/
// frequency/relationship references) and the test wires ZERO tool signals
// (fixedTools left at its zero value: toolCalls=0, distinctTools=0). This
// satisfies triage's cleanResolve() floor (positive evidence + confidence>=4 +
// tools not empty) so an UN-forced finding terminates at triage in exactly one
// model call — the baseline this test's invariance check is measured against.
func cleanResolveBackend(t *testing.T) *cannedbackend.CannedBackend {
	t.Helper()
	return &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(callIndex int) string {
			return `{"action":"resolve","confidence":5,"positive_evidence":true,` +
				`"reason":"alice-known logged in from a new IP in a familiar region; no indicators of compromise."}`
		},
	}
}

// severityDirective builds a "severity" Directive matching the fixture
// finding's (source/type/actor) key, mirroring what `mallcop feedback <id>
// severity <level>` persists (cli/feedback.go).
func severityOverrideDirective(t *testing.T, pattern, severity string) store.Directive {
	t.Helper()
	meta, err := json.Marshal(map[string]string{"severity": severity})
	if err != nil {
		t.Fatalf("marshal severity meta: %v", err)
	}
	return store.Directive{Op: "severity", Pattern: pattern, Meta: json.RawMessage(meta)}
}

// runSeverityInvarianceScan runs the real pipeline.Run() once over the
// lowSeverityLoginEvent fixture, optionally with a "severity critical"
// directive pre-seeded into the store, and returns the summary, the model
// call count, and the persisted finding's Severity label. Each call gets its
// own fresh git store (directives differ; a shared store would also make the
// second run's dedupe skip the first run's already-committed event).
func runSeverityInvarianceScan(t *testing.T, withDirective bool) (pipeline.Summary, int, string) {
	t.Helper()
	root := useShippedCorpus(t)

	be := cleanResolveBackend(t)
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	st := newGitStore(t)

	findingPattern := "detector:unusual-login/unusual-login/alice-known"
	if withDirective {
		d := severityOverrideDirective(t, findingPattern, "critical")
		if _, err := st.Append(store.KindDirectives, d); err != nil {
			t.Fatalf("append severity directive: %v", err)
		}
	}

	events := []event.Event{lowSeverityLoginEvent()}
	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, events)),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		Baseline:  unusualLoginBaseline(),
		Cascade:   agent.CascadeOptions{RepoRoot: root, Tools: fixedTools{text: "no tool evidence gathered"}},
		Workers:   1,
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run (withDirective=%v): %v", withDirective, err)
	}
	if sum.FindingsDetected != 1 {
		t.Fatalf("withDirective=%v: FindingsDetected = %d, want exactly 1 (fixture must produce a single, deterministic finding); summary=%+v",
			withDirective, sum.FindingsDetected, sum)
	}

	raws, err := st.Load(store.KindFindings)
	if err != nil {
		t.Fatalf("load stored findings: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("withDirective=%v: stored findings count = %d, want 1", withDirective, len(raws))
	}
	var stored struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(raws[0], &stored); err != nil {
		t.Fatalf("unmarshal stored finding: %v", err)
	}

	return sum, be.CallCount(), stored.Severity
}

// TestSeverityOverride_DoesNotChangeCommitteeVerdict is the mallcoppro-e38
// enforcement test: the SAME fixture, resolved with and without an operator
// "severity critical" directive, must produce an IDENTICAL committee
// disposition and IDENTICAL model call count — the directive may change ONLY
// the displayed/persisted Severity label.
func TestSeverityOverride_DoesNotChangeCommitteeVerdict(t *testing.T) {
	baseSum, baseCalls, baseSeverity := runSeverityInvarianceScan(t, false)
	overrideSum, overrideCalls, overrideSeverity := runSeverityInvarianceScan(t, true)

	// R9 invariant: the operator's severity directive must NOT change the
	// committee's disposition of the finding.
	if baseSum.Resolved != overrideSum.Resolved {
		t.Errorf("Resolved differs with a severity directive present: no-directive=%d, with-directive=%d — "+
			"the operator's severity relabel changed the committee's disposition (R9 violation)",
			baseSum.Resolved, overrideSum.Resolved)
	}
	if baseSum.Escalated != overrideSum.Escalated {
		t.Errorf("Escalated differs with a severity directive present: no-directive=%d, with-directive=%d — "+
			"the operator's severity relabel changed the committee's disposition (R9 violation)",
			baseSum.Escalated, overrideSum.Escalated)
	}
	if baseSum.Investigated != overrideSum.Investigated {
		t.Errorf("Investigated differs with a severity directive present: no-directive=%d, with-directive=%d",
			baseSum.Investigated, overrideSum.Investigated)
	}

	// The stronger, mechanism-level proof: an identical model call count means
	// the finding took the SAME cascade path (triage-terminal vs
	// forced-to-investigate) regardless of the directive. Under the pre-fix
	// bug, the "critical" override forced triageResolveMustEscalate to hand the
	// finding off to investigate, so the with-directive run made MORE model
	// calls than the no-directive run for the identical finding.
	if baseCalls != overrideCalls {
		t.Errorf("model call count differs with a severity directive present: no-directive=%d, with-directive=%d — "+
			"the severity override changed which cascade tier(s) ran (R9 violation: the operator's annotation "+
			"fed back into the committee's routing)", baseCalls, overrideCalls)
	}
	if baseCalls != 1 {
		t.Errorf("no-directive run made %d model calls, want exactly 1 (clean triage-terminal resolve) — "+
			"fixture precondition not met, the rest of this test's proof is not meaningful", baseCalls)
	}

	// The severity LABEL must still differ — proving the override remains a
	// real, working display/output annotation and this isn't a vacuous test.
	if baseSeverity != "low" {
		t.Errorf("no-directive stored finding Severity = %q, want %q (the real detector severity)", baseSeverity, "low")
	}
	if overrideSeverity != "critical" {
		t.Errorf("with-directive stored finding Severity = %q, want %q (the operator's override, applied to the DISPLAY copy only)",
			overrideSeverity, "critical")
	}
}
