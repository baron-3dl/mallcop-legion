package inquest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func escalatedForSource(id, source string) EscalatedFinding {
	return EscalatedFinding{
		Finding:    finding.Finding{ID: id, Source: source, Actor: "a", Type: "assume_role", Timestamp: time.Now()},
		Resolution: ResolutionRef{Action: "escalate", Reason: "test"},
	}
}

// TestRunAll_PrioritizeDirective_TargetSourceWeightsAttention proves the
// item's DONE condition on the inquest side: a 'prioritize' directive with
// target_kind="source" weights which escalated finding a budget-limited scan
// spends its metered narrate call on. finding-aaa (source detector:aaa) and
// finding-zzz (source detector:zzz) both need investigation; with MaxPerScan=1
// and no directive, the deterministic finding-ID sort picks finding-aaa
// (alphabetically first) — proven by the baseline sub-test. A prioritize
// directive naming detector:zzz must flip that: finding-zzz gets the one
// metered call instead, finding-aaa degrades to absent-budget.
func TestRunAll_PrioritizeDirective_TargetSourceWeightsAttention(t *testing.T) {
	findings := []EscalatedFinding{
		escalatedForSource("finding-aaa", "detector:aaa"),
		escalatedForSource("finding-zzz", "detector:zzz"),
	}
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"attention-weight narrative text."}`}

	t.Run("baseline_no_directive_picks_alphabetically_first", func(t *testing.T) {
		s := newTempStore(t)
		in := Input{Store: s, Client: client, Findings: findings, Config: Config{Enabled: true, MaxPerScan: 1, MaxTokens: 1024}}
		out := RunAll(context.Background(), in)
		if out.Investigated != 1 || len(out.FreshOKIDs) != 1 || out.FreshOKIDs[0] != "finding-aaa" {
			t.Fatalf("baseline Outcome = %+v, want finding-aaa investigated first", out)
		}
		rec := readRecord(t, in, "finding-zzz")
		if rec.NarrativeStatus != StatusAbsentBudget {
			t.Fatalf("finding-zzz NarrativeStatus = %q, want absent-budget", rec.NarrativeStatus)
		}
	})

	t.Run("prioritize_directive_flips_which_finding_gets_the_budget", func(t *testing.T) {
		s := newTempStore(t)
		meta, err := json.Marshal(map[string]any{"target_kind": "source", "weight": 5.0})
		if err != nil {
			t.Fatalf("marshal meta: %v", err)
		}
		if _, err := s.Append(store.KindDirectives, store.Directive{
			Op: "prioritize", Pattern: "detector:zzz", Actor: "operator",
			Reason: "focus on the payments connector", Meta: meta,
		}); err != nil {
			t.Fatalf("append prioritize directive: %v", err)
		}
		in := Input{Store: s, Client: client, Findings: findings, Config: Config{Enabled: true, MaxPerScan: 1, MaxTokens: 1024}}
		out := RunAll(context.Background(), in)
		if out.Investigated != 1 || len(out.FreshOKIDs) != 1 || out.FreshOKIDs[0] != "finding-zzz" {
			t.Fatalf("prioritized Outcome = %+v, want finding-zzz investigated first", out)
		}
		rec := readRecord(t, in, "finding-aaa")
		if rec.NarrativeStatus != StatusAbsentBudget {
			t.Fatalf("finding-aaa NarrativeStatus = %q, want absent-budget", rec.NarrativeStatus)
		}
	})
}

// TestRunAll_PrioritizeDirective_NoDirectivesPreservesFindingIDOrder proves
// the additive/no-effect-by-default case: with NO directives on the stream at
// all (in.Store.LoadDirectives returns an empty slice, not an error), RunAll's
// outcome is byte-identical to the pre-Gap-E2 finding-ID order — the same
// assertion TestRunAll_BudgetGate already makes, repeated here as this
// package's own regression proof that wiring attentionWeight in did not
// change the zero-directives path.
func TestRunAll_PrioritizeDirective_NoDirectivesPreservesFindingIDOrder(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"no-directive narrative text."}`}
	findings := []EscalatedFinding{
		escalatedForSource("finding-b", "detector:b"),
		escalatedForSource("finding-a", "detector:a"),
	}
	in := Input{Store: s, Client: client, Findings: findings, Config: okConfig()}
	out := RunAll(context.Background(), in)
	if out.Investigated != 2 {
		t.Fatalf("Investigated = %d, want 2", out.Investigated)
	}
	if len(out.FreshOKIDs) != 2 || out.FreshOKIDs[0] != "finding-a" || out.FreshOKIDs[1] != "finding-b" {
		t.Fatalf("FreshOKIDs = %v, want [finding-a finding-b] (finding-ID order preserved)", out.FreshOKIDs)
	}
}
