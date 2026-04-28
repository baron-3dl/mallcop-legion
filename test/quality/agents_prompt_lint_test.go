package quality_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeepInvestigatePromptExists verifies that agents/deep-investigate/POST.md
// exists and contains the three hypothesis branch markers required by F1D.
func TestDeepInvestigatePromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "deep-investigate", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/deep-investigate/POST.md (F1D)", promptPath, err)
	}
	content := string(data)

	// Required hypothesis branch markers (case-insensitive match on the keyword)
	hypotheses := []struct {
		label   string
		keyword string
	}{
		{"benign hypothesis branch", "hypothesis: benign"},
		{"malicious hypothesis branch", "hypothesis: malicious"},
		{"incomplete hypothesis branch", "hypothesis: incomplete"},
	}

	for _, h := range hypotheses {
		lower := strings.ToLower(content)
		if !strings.Contains(lower, strings.ToLower(h.keyword)) {
			t.Errorf("agents/deep-investigate/POST.md: missing %s — expected to find %q", h.label, h.keyword)
		}
	}

	// Required structural directives
	directives := []struct {
		label string
		token string
	}{
		{"JSON output format", `"finding_id"`},
		{"JSON output format", `"action"`},
		{"JSON output format", `"confidence"`},
		{"fail-safe escalate on missing hypothesis", "malformed"},
		{"benign directive: confirming evidence", "confirming evidence"},
		{"malicious directive: attack vector", "attack vector"},
		{"incomplete directive: disambiguate", "disambiguate"},
		{"hard constraint: no remediate action for deep workers", "remediate"},
		{"partial transcript read directive", "partial_transcript_path"},
	}

	for _, d := range directives {
		lower := strings.ToLower(content)
		if !strings.Contains(lower, strings.ToLower(d.token)) {
			t.Errorf("agents/deep-investigate/POST.md: missing directive %q — expected token %q", d.label, d.token)
		}
	}
}

// TestInvestigateMergePromptExists verifies that agents/investigate-merge/POST.md
// exists and contains the three aggregation rules required by F1E.
func TestInvestigateMergePromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "investigate-merge", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/investigate-merge/POST.md (F1E)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// Required aggregation rules
	aggregationRules := []struct {
		label string
		token string
	}{
		{"all-3-agree rule", "all 3 agree"},
		{"2-agree-1-dissent rule", "2 agree"},
		{"all-3-disagree rule", "all 3 disagree"},
		{"confidence max for all-agree", "max"},
		{"confidence penalty for 2v1: -0.1", "0.1"},
		{"system-genuinely-uncertain flag", "system genuinely uncertain"},
		{"escalate-to-stage-c for all-disagree", "escalate-to-stage-c"},
		{"evidence aggregation not vote", "not"},
	}

	for _, r := range aggregationRules {
		if !strings.Contains(lower, strings.ToLower(r.token)) {
			t.Errorf("agents/investigate-merge/POST.md: missing aggregation rule %q — expected token %q", r.label, r.token)
		}
	}

	// Must require reading transcripts, not just verdicts
	transcriptTokens := []string{
		"get_session_transcript",
		"fetch_work_output",
	}
	for _, tok := range transcriptTokens {
		if !strings.Contains(content, tok) {
			t.Errorf("agents/investigate-merge/POST.md: must reference %q — aggregation must read transcripts, not just verdicts", tok)
		}
	}

	// JSON output format
	jsonTokens := []string{`"finding_id"`, `"action"`, `"confidence"`}
	for _, tok := range jsonTokens {
		if !strings.Contains(content, tok) {
			t.Errorf("agents/investigate-merge/POST.md: missing JSON output field %q", tok)
		}
	}
}

// TestSmokeFixturesWellFormed verifies that the 3 smoke-merge fixture JSON files
// exist and conform to the expected shape for investigate-merge smoke testing.
func TestSmokeFixturesWellFormed(t *testing.T) {
	root := repoRoot(t)

	fixtures := []struct {
		name     string
		path     string
		ruleType string // "all-agree", "2-agree-1-dissent", or "all-disagree"
	}{
		{
			name:     "smoke-merge-agree",
			path:     filepath.Join(root, "docs", "academy", "smoke-merge-agree.json"),
			ruleType: "all-agree",
		},
		{
			name:     "smoke-merge-split",
			path:     filepath.Join(root, "docs", "academy", "smoke-merge-split.json"),
			ruleType: "2-agree-1-dissent",
		},
		{
			name:     "smoke-merge-disagree",
			path:     filepath.Join(root, "docs", "academy", "smoke-merge-disagree.json"),
			ruleType: "all-disagree",
		},
	}

	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			data, err := os.ReadFile(fix.path)
			if err != nil {
				t.Fatalf("fixture file missing: %s: %v", fix.path, err)
			}

			// Must be valid JSON
			var doc map[string]interface{}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("fixture %s is not valid JSON: %v", fix.name, err)
			}

			// Must have finding_id
			if _, ok := doc["finding_id"]; !ok {
				t.Errorf("fixture %s: missing top-level 'finding_id'", fix.name)
			}

			// Must have deep_worker_verdicts array with 3 entries
			verdicts, ok := doc["deep_worker_verdicts"]
			if !ok {
				t.Errorf("fixture %s: missing 'deep_worker_verdicts' array", fix.name)
			} else {
				arr, ok := verdicts.([]interface{})
				if !ok {
					t.Errorf("fixture %s: 'deep_worker_verdicts' must be an array", fix.name)
				} else if len(arr) != 3 {
					t.Errorf("fixture %s: 'deep_worker_verdicts' must have exactly 3 entries, got %d", fix.name, len(arr))
				} else {
					// Each entry must have hypothesis, item_id, verdict
					hypotheses := map[string]bool{}
					for i, entry := range arr {
						m, ok := entry.(map[string]interface{})
						if !ok {
							t.Errorf("fixture %s: deep_worker_verdicts[%d] must be an object", fix.name, i)
							continue
						}
						for _, field := range []string{"hypothesis", "item_id", "verdict", "evidence_chain"} {
							if _, ok := m[field]; !ok {
								t.Errorf("fixture %s: deep_worker_verdicts[%d] missing field %q", fix.name, i, field)
							}
						}
						hyp, _ := m["hypothesis"].(string)
						hypotheses[hyp] = true

						// Each verdict must have the right shape
						if v, ok := m["verdict"].(map[string]interface{}); ok {
							for _, vf := range []string{"finding_id", "action", "reason", "confidence"} {
								if _, ok := v[vf]; !ok {
									t.Errorf("fixture %s: deep_worker_verdicts[%d].verdict missing field %q", fix.name, i, vf)
								}
							}
						}
					}

					// All 3 hypotheses must be represented
					for _, h := range []string{"benign", "malicious", "incomplete"} {
						if !hypotheses[h] {
							t.Errorf("fixture %s: missing hypothesis %q in deep_worker_verdicts", fix.name, h)
						}
					}
				}
			}

			// Must have expected_aggregation with the rule field
			agg, ok := doc["expected_aggregation"]
			if !ok {
				t.Errorf("fixture %s: missing 'expected_aggregation'", fix.name)
			} else {
				aggMap, ok := agg.(map[string]interface{})
				if !ok {
					t.Errorf("fixture %s: 'expected_aggregation' must be an object", fix.name)
				} else {
					rule, _ := aggMap["rule"].(string)
					if rule != fix.ruleType {
						t.Errorf("fixture %s: expected_aggregation.rule=%q, want %q", fix.name, rule, fix.ruleType)
					}
				}
			}
		})
	}
}

// TestSplitFixtureConfidencePenalty verifies that the 2v1 fixture captures
// the exact -0.1 confidence penalty (not rounded, not approximated).
func TestSplitFixtureConfidencePenalty(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "docs", "academy", "smoke-merge-split.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON in %s: %v", path, err)
	}

	agg, ok := doc["expected_aggregation"].(map[string]interface{})
	if !ok {
		t.Skip("expected_aggregation not present or not object — covered by TestSmokeFixturesWellFormed")
	}

	// Verify penalty = 0.1 exactly
	penalty, ok := agg["confidence_penalty"].(float64)
	if !ok {
		t.Fatalf("expected_aggregation.confidence_penalty missing or not a number")
	}
	if penalty != 0.1 {
		t.Errorf("confidence_penalty = %v, want exactly 0.1 (F1E spec: 'conf -= 0.1, exact, do not round')", penalty)
	}

	// Verify the formula makes sense: final = mean(majority_confidences) - 0.1
	majorityConfs, ok := agg["majority_confidences"].([]interface{})
	if !ok || len(majorityConfs) != 2 {
		t.Skip("majority_confidences not present or not 2-element — skip formula check")
	}
	c1, ok1 := majorityConfs[0].(float64)
	c2, ok2 := majorityConfs[1].(float64)
	if !ok1 || !ok2 {
		t.Skip("majority_confidences elements not floats — skip formula check")
	}
	expectedFinal := (c1+c2)/2.0 - 0.1
	actualFinal, ok := agg["final_confidence"].(float64)
	if !ok {
		t.Skip("final_confidence missing — skip formula check")
	}
	// Allow for floating point representation (1e-9 tolerance)
	diff := expectedFinal - actualFinal
	if diff < 0 {
		diff = -diff
	}
	if diff > 1e-9 {
		t.Errorf("final_confidence formula mismatch: mean(%v,%v) - 0.1 = %v, but fixture says %v",
			c1, c2, expectedFinal, actualFinal)
	}
}
