package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/inquest"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// focusDirective builds a focus/watch-closer Directive whose Meta.weight is
// the given value, mirroring what `mallcop feedback <id> watch` persists.
func focusDirective(op, pattern string, weight float64) store.Directive {
	meta, err := json.Marshal(map[string]float64{"weight": weight})
	if err != nil {
		panic(err)
	}
	return store.Directive{Op: op, Pattern: pattern, Meta: json.RawMessage(meta)}
}

// severityDirective builds a severity Directive, mirroring what `mallcop
// feedback <id> severity <level>` persists.
func severityDirective(pattern, severity string) store.Directive {
	meta, err := json.Marshal(map[string]string{"severity": severity})
	if err != nil {
		panic(err)
	}
	return store.Directive{Op: "severity", Pattern: pattern, Meta: json.RawMessage(meta)}
}

// TestRankFindings_FocusRaisesRank is the enforcement test for the "finding
// ranking" half of Gap C (mallcoppro-4da): a focus directive on f2 (an
// otherwise-later finding by ID) moves it AHEAD of f1 and f3 in RankFindings'
// output. watch-closer is proven separately below to raise weight too.
func TestRankFindings_FocusRaisesRank(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
		mkFinding("f3", "detector:priv-escalation", "priv-escalation", "carol"),
	}
	directives := []store.Directive{
		focusDirective("focus", "detector:new-actor/new-actor/bob", 5.0),
	}
	d := NewDirectiveDispatcher()
	d.Register("focus", attentionWeightConsumer)
	ranked := d.RankFindings(findings, directives)
	if ranked[0].ID != "f2" {
		t.Fatalf("expected focused finding f2 ranked first, got order %v", idsOf(ranked))
	}
	// The unfocused pair keep their deterministic ID-order tiebreak.
	if ranked[1].ID != "f1" || ranked[2].ID != "f3" {
		t.Fatalf("expected f1,f3 order preserved among 0-weight findings, got %v", idsOf(ranked))
	}
}

// TestRankFindings_WatchCloserRaisesRank proves watch-closer is the SAME
// "raise" direction as focus (the opposite of suppress), per the item's
// explicit "watch-closer = raise, opposite of suppress" contract.
func TestRankFindings_WatchCloserRaisesRank(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		focusDirective("watch-closer", "detector:new-actor/new-actor/bob", 3.0),
	}
	d := NewDirectiveDispatcher()
	d.Register("watch-closer", attentionWeightConsumer)
	ranked := d.RankFindings(findings, directives)
	if ranked[0].ID != "f2" {
		t.Fatalf("expected watch-closer finding f2 ranked first, got order %v", idsOf(ranked))
	}
}

// TestRankFindings_NoDirectiveWeightBumpDefaultsPositive proves a bare focus
// directive (no explicit Meta.weight) still raises rank rather than being a
// silent no-op — defaultFocusWeight's contract.
func TestRankFindings_NoDirectiveWeightBumpDefaultsPositive(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		{Op: "focus", Pattern: "detector:new-actor/new-actor/bob"}, // no Meta at all
	}
	d := NewDirectiveDispatcher()
	d.Register("focus", attentionWeightConsumer)
	ranked := d.RankFindings(findings, directives)
	if ranked[0].ID != "f2" {
		t.Fatalf("expected bare focus directive to still raise f2's rank, got order %v", idsOf(ranked))
	}
}

// TestInquestRunAll_AttentionWeightBudgetsHigherWeightFirst is the
// enforcement test for the "core/inquest investigation-depth budget" half of
// Gap C: with MaxPerScan=1 (budget for exactly ONE metered call) and two
// escalated findings where f-low sorts first by ID but f-high carries the
// focus attention weight, RunAll spends its one call on f-high, not f-low —
// proving AttentionWeights actually reorders budget consumption, not just an
// inert field.
func TestInquestRunAll_AttentionWeightBudgetsHigherWeightFirst(t *testing.T) {
	fLow := mkFinding("a-low", "detector:secrets-exposure", "secrets-exposure", "alice")
	fHigh := mkFinding("z-high", "detector:new-actor", "new-actor", "bob")

	escalated := []inquest.EscalatedFinding{
		{Finding: fLow, Resolution: inquest.ResolutionRef{Action: "escalate", Reason: "test"}},
		{Finding: fHigh, Resolution: inquest.ResolutionRef{Action: "escalate", Reason: "test"}},
	}
	directives := []store.Directive{
		focusDirective("focus", "detector:new-actor/new-actor/bob", 10.0),
	}
	d := NewDirectiveDispatcher()
	d.Register("focus", attentionWeightConsumer)
	findings := []finding.Finding{fLow, fHigh}
	weights := d.AttentionWeights(findings, directives)

	if weights["a-low"] != 0 {
		t.Fatalf("expected a-low to carry zero attention weight, got %v", weights["a-low"])
	}
	if weights["z-high"] != 10.0 {
		t.Fatalf("expected z-high to carry the focus directive's weight, got %v", weights["z-high"])
	}

	client := &attentionOrderClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"attention-order test."}`}
	out := inquest.RunAll(context.Background(), inquest.Input{
		Store:            newTestStoreForAttention(t),
		Client:           client,
		Findings:         escalated,
		MallcopVersion:   "test",
		Config:           inquest.Config{Enabled: true, MaxPerScan: 1},
		AttentionWeights: weights,
	})
	if out.Investigated != 1 {
		t.Fatalf("expected exactly 1 investigated call (MaxPerScan=1), got %d", out.Investigated)
	}
	if len(client.calledFor) != 1 || client.calledFor[0] != "z-high" {
		t.Fatalf("expected the SINGLE budgeted call to land on the higher-weight finding z-high, got %v", client.calledFor)
	}
}

// TestApplySeverityOverrides_ChangesLabelOnly is the enforcement test for
// the "severity directive changes finding.Severity" half of the DONE
// condition, and proves R9's other half in the same breath: nothing here
// touches a committee verdict (Severity is the only field the consumer
// reads/writes; ID/Source/Type/Actor/Timestamp/Reason/Evidence/EventIDs are
// untouched, and there is no dispatch to core/agent anywhere in this path).
func TestApplySeverityOverrides_ChangesLabelOnly(t *testing.T) {
	orig := mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice")
	orig.Severity = "low"
	findings := []finding.Finding{orig}
	directives := []store.Directive{
		severityDirective("detector:secrets-exposure/secrets-exposure/alice", "critical"),
	}
	d := NewDirectiveDispatcher()
	d.Register("severity", severityOverrideConsumer)
	out := d.ApplySeverityOverrides(findings, directives)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Fatalf("expected Severity overridden to critical, got %q", out[0].Severity)
	}
	// Everything else about the finding is untouched — a severity directive
	// relabels, it does not re-derive or re-vote the finding.
	if out[0].ID != orig.ID || out[0].Source != orig.Source || out[0].Type != orig.Type ||
		out[0].Actor != orig.Actor || out[0].Reason != orig.Reason || !out[0].Timestamp.Equal(orig.Timestamp) {
		t.Fatalf("severity override must change ONLY Severity, got %+v want %+v (Severity aside)", out[0], orig)
	}
}

// TestApplySeverityOverrides_NoMatchLeavesSeverityUntouched proves the
// no-directive path is a true no-op (R9 default-safe behavior).
func TestApplySeverityOverrides_NoMatchLeavesSeverityUntouched(t *testing.T) {
	orig := mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice")
	orig.Severity = "medium"
	d := NewDirectiveDispatcher()
	d.Register("severity", severityOverrideConsumer)
	out := d.ApplySeverityOverrides([]finding.Finding{orig}, nil)
	if out[0].Severity != "medium" {
		t.Fatalf("expected Severity untouched with no directives, got %q", out[0].Severity)
	}
}

// TestFocusSeverity_NeverSuppresses is the R9 enforcement test proving
// neither attention consumer ever drops a finding — the hard line the item
// names explicitly: naming/weighting/annotation only, NEVER a verdict
// (drop/keep) override. Run through the FULL Apply path (the drop decision),
// not just the consumer functions in isolation.
func TestFocusSeverity_NeverSuppresses(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	directives := []store.Directive{
		focusDirective("focus", "detector:secrets-exposure/secrets-exposure/alice", 100.0),
		severityDirective("detector:secrets-exposure/secrets-exposure/alice", "critical"),
	}
	d := NewDirectiveDispatcher()
	d.Register("focus", attentionWeightConsumer)
	d.Register("severity", severityOverrideConsumer)
	kept := d.Apply(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("focus/severity directives must never drop a finding, got %d kept", len(kept))
	}
}

func idsOf(fs []finding.Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.ID
	}
	return ids
}

// attentionOrderClient is a minimal agent.Client stub recording which
// finding IDs it was asked to narrate, in call order (parsed out of the
// prompt text, which core/inquest's narrate prompt embeds — see
// core/inquest/narrate.go). It always returns a syntactically valid "ok"
// narrate response so RunAll's one call per finding counts as Investigated
// (the ordering claim under test does not depend on narrative content).
type attentionOrderClient struct {
	reply     string
	calledFor []string
}

func (c *attentionOrderClient) Messages(_ context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	var text string
	if len(req.Messages) > 0 && len(req.Messages[0].Content) > 0 {
		text = req.Messages[0].Content[0].Text
	}
	if strings.Contains(text, "z-high") {
		c.calledFor = append(c.calledFor, "z-high")
	} else if strings.Contains(text, "a-low") {
		c.calledFor = append(c.calledFor, "a-low")
	}
	return agent.MessagesResponse{
		StopReason: "end_turn",
		Content:    []agent.ContentBlock{{Type: "text", Text: c.reply}},
	}, nil
}

// newTestStoreForAttention git-inits a temp repo and opens a real
// core/store over it — mirrors core/inquest/helpers_test.go's newTempStore
// (that helper is unexported in package inquest_test, so this package needs
// its own copy; RunAll requires a real store, not a fake).
func newTestStoreForAttention(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}
