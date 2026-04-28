package quality_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHealPromptExists verifies that agents/heal/POST.md exists and contains
// the key directives required by F1H: narrow parser-fix scope (log_format_drift
// only), three scenario types, patch structure, annotate-finding + resolve-finding
// calls, and the security injection defense section.
func TestHealPromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "heal", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/heal/POST.md (F1H)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// Required scope: heal only responds to log_format_drift findings.
	if !strings.Contains(lower, "log_format_drift") {
		t.Errorf("agents/heal/POST.md: missing 'log_format_drift' — heal must specify its trigger finding type")
	}

	// Required scenario vocabulary
	scenarios := []string{"new_field", "renamed_field", "format_change"}
	for _, s := range scenarios {
		if !strings.Contains(lower, strings.ToLower(s)) {
			t.Errorf("agents/heal/POST.md: missing scenario %q — heal must identify all three drift scenarios", s)
		}
	}

	// Required patch fields
	patchFields := []string{"scenario", "app_name", "before", "after", "reason", "confidence"}
	for _, f := range patchFields {
		if !strings.Contains(lower, strings.ToLower(f)) {
			t.Errorf("agents/heal/POST.md: missing patch field %q — patch dict must include this field", f)
		}
	}

	// Required tool calls
	toolCalls := []string{"annotate-finding", "resolve-finding"}
	for _, tc := range toolCalls {
		if !strings.Contains(lower, strings.ToLower(tc)) {
			t.Errorf("agents/heal/POST.md: missing tool call %q — heal output must call this tool", tc)
		}
	}

	// Security injection defense section
	if !strings.Contains(content, "USER_DATA_BEGIN") {
		t.Errorf("agents/heal/POST.md: missing security section with USER_DATA_BEGIN marker")
	}
	if !strings.Contains(content, "USER_DATA_END") {
		t.Errorf("agents/heal/POST.md: missing security section with USER_DATA_END marker")
	}

	// Proposal is a patch, not an automatic apply
	if !strings.Contains(lower, "proposal") && !strings.Contains(lower, "not applied") {
		t.Errorf("agents/heal/POST.md: must state that the patch is a proposal, not automatically applied")
	}

	// read-finding tool call for loading the finding record
	if !strings.Contains(lower, "read-finding") {
		t.Errorf("agents/heal/POST.md: missing 'read-finding' tool reference — heal must use read-finding to load the full finding")
	}

	// Negative assertions: heal scope must stay narrow. The Python source-of-truth
	// is parser-fix only. Broad-remediation language from the prior legion version
	// must not regress in. These tokens are the specific writes the old POST.md
	// authorized; heal must NEVER do these (those belong to task:escalate).
	forbiddenTokens := []string{
		"revoke-credential",
		"quarantine-user",
		"rotate-key",
		"disable-account",
		"revert-config",
		"remediate-action",
		"approve-action",
		"escalate-to-stage-c",
		"escalate-to-investigator",
		"escalate-to-deep",
		"request-approval",
	}
	for _, ft := range forbiddenTokens {
		if strings.Contains(lower, ft) {
			t.Errorf("agents/heal/POST.md: forbidden token %q present — heal scope must stay narrow (parser-fix only); broad-remediation tools belong to task:escalate, not task:heal", ft)
		}
	}
}

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

// TestTriagePromptExists verifies that agents/triage/POST.md exists and contains
// the key directives required by F1B: 4-step process, all four hard rules,
// confidence 1-5 scale, security section, and escalate-to-investigator reference.
func TestTriagePromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "triage", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/triage/POST.md (F1B)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// Required 4-step process markers
	steps := []struct {
		label string
		token string
	}{
		{"Step 1: check-baseline", "check-baseline"},
		{"Step 2: search-events", "search-events"},
		{"Step 3: Analyze (A/B/C/D)", "routine for this actor"},
		{"Step 4: Decide", "decide"},
	}
	for _, s := range steps {
		if !strings.Contains(lower, strings.ToLower(s.token)) {
			t.Errorf("agents/triage/POST.md: missing step %q — expected token %q", s.label, s.token)
		}
	}

	// Required hard rules (non-negotiable)
	hardRules := []struct {
		label string
		token string
	}{
		{"privilege escalate rule", "privilege changes"},
		{"log format drift escalate rule", "log format drift"},
		{"confidence floor escalate rule (conf<3 escalate)", "confidence"},
		{"positive evidence requirement", "positive evidence"},
	}
	for _, r := range hardRules {
		if !strings.Contains(lower, strings.ToLower(r.token)) {
			t.Errorf("agents/triage/POST.md: missing hard rule %q — expected token %q", r.label, r.token)
		}
	}

	// Confidence scale 1-5
	if !strings.Contains(content, "1-5") && !strings.Contains(content, "1–5") {
		t.Errorf("agents/triage/POST.md: missing confidence 1-5 scale")
	}

	// Security injection defense section
	if !strings.Contains(content, "USER_DATA_BEGIN") {
		t.Errorf("agents/triage/POST.md: missing security section with USER_DATA_BEGIN marker")
	}
	if !strings.Contains(content, "USER_DATA_END") {
		t.Errorf("agents/triage/POST.md: missing security section with USER_DATA_END marker")
	}

	// Required tool: escalate-to-investigator
	if !strings.Contains(lower, "escalate-to-investigator") {
		t.Errorf("agents/triage/POST.md: missing 'escalate-to-investigator' — triage must reference the handoff tool")
	}

	// Negative assertions: triage must NOT reference investigate-level or escalate-level tools
	forbiddenTools := []string{
		"escalate-to-stage-c",
		"escalate-to-deep",
		"create-investigate-merge",
		"write-partial-transcript",
		"remediate-action",
		"request-approval",
		"message-operator",
		"list-actions",
		"load-skill",
		"approve-action",
	}
	for _, ft := range forbiddenTools {
		if strings.Contains(lower, ft) {
			t.Errorf("agents/triage/POST.md: forbidden tool %q present — triage is stage-A only; deeper tools belong to investigate/escalate", ft)
		}
	}
}

// TestInvestigatePromptExists verifies that agents/investigate/POST.md exists and
// contains the key directives required by F1C: 5-check pre-resolution checklist,
// hard constraints, credential theft test, chase-provenance, weigh-signals,
// load-skill reference, and — critically — the §Fan-out on Uncertainty section
// with the verbatim 'task:deep-investigate' string (R1 grep check).
func TestInvestigatePromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "investigate", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/investigate/POST.md (F1C)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// Pre-resolution checklist (5 checks — must all be present by keyword)
	checklistItems := []struct {
		label string
		token string
	}{
		{"EVIDENCE check", "evidence"},
		{"ADVERSARY check", "adversary"},
		{"DISCONFIRM check", "disconfirm"},
		{"BOUNDARY check", "boundary"},
		{"BLAST RADIUS check", "blast radius"},
	}
	for _, c := range checklistItems {
		if !strings.Contains(lower, strings.ToLower(c.token)) {
			t.Errorf("agents/investigate/POST.md: missing pre-resolution checklist item %q — expected token %q", c.label, c.token)
		}
	}

	// Hard constraints keywords
	hardConstraints := []struct {
		label string
		token string
	}{
		{"privilege changes hard constraint", "privilege changes always"},
		{"structural drift hard constraint", "structural drift"},
		{"prior resolutions constraint", "prior resolutions"},
		{"in-band confirmation constraint", "in-band confirmation"},
	}
	for _, hc := range hardConstraints {
		if !strings.Contains(lower, strings.ToLower(hc.token)) {
			t.Errorf("agents/investigate/POST.md: missing hard constraint %q — expected token %q", hc.label, hc.token)
		}
	}

	// Credential theft test section
	if !strings.Contains(lower, "credential theft test") {
		t.Errorf("agents/investigate/POST.md: missing 'Credential Theft Test' section")
	}

	// Chase provenance section
	if !strings.Contains(lower, "chase provenance") {
		t.Errorf("agents/investigate/POST.md: missing 'Chase provenance' section")
	}

	// Weigh signals section
	if !strings.Contains(lower, "weigh signals") {
		t.Errorf("agents/investigate/POST.md: missing 'Weigh signals' section")
	}

	// load-skill reference
	if !strings.Contains(lower, "load-skill") {
		t.Errorf("agents/investigate/POST.md: missing 'load-skill' reference — investigate must document the skill-loading mechanism")
	}

	// Security injection defense
	if !strings.Contains(content, "USER_DATA_BEGIN") {
		t.Errorf("agents/investigate/POST.md: missing security section with USER_DATA_BEGIN marker")
	}

	// Fan-out section — R1 grep check: 'task:deep-investigate' MUST appear verbatim
	if !strings.Contains(content, "task:deep-investigate") {
		t.Errorf("agents/investigate/POST.md: missing verbatim 'task:deep-investigate' string — §Fan-out on Uncertainty section must be present (F1C requirement, F2 enforcement hook is separate)")
	}

	// Fan-out section required tokens
	fanoutTokens := []struct {
		label string
		token string
	}{
		{"fan-out section header", "fan-out on uncertainty"},
		{"confidence threshold 0.55", "0.55"},
		{"deep-investigate benign hypothesis", "hypothesis:benign"},
		{"deep-investigate malicious hypothesis", "hypothesis:malicious"},
		{"deep-investigate incomplete hypothesis", "hypothesis:incomplete"},
		{"investigate-merge item creation", "task:investigate-merge"},
		{"partial transcript step", "partial transcript"},
	}
	for _, ft := range fanoutTokens {
		if !strings.Contains(lower, strings.ToLower(ft.token)) {
			t.Errorf("agents/investigate/POST.md: missing fan-out token %q — expected %q", ft.label, ft.token)
		}
	}

	// Negative assertions: investigate must NOT have escalate-to-investigator (that's triage's tool)
	// and must NOT have stage-C consumer tools (those belong to escalate)
	forbiddenTools := []string{
		"escalate-to-investigator",
		"remediate-action",
		"request-approval",
		"message-operator",
		"list-actions",
		"approve-action",
	}
	for _, ft := range forbiddenTools {
		if strings.Contains(lower, ft) {
			t.Errorf("agents/investigate/POST.md: forbidden tool %q present — investigate is stage-B; this tool belongs to triage or escalate", ft)
		}
	}
}

// TestEscalatePromptExists verifies that agents/escalate/POST.md exists and
// contains all four branch labels, correct branch selection logic, tool references,
// and — critically — does NOT contain escalation-chain tools (escalate is terminal).
func TestEscalatePromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "escalate", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/escalate/POST.md (F1F)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// Required 4 branch labels (case-insensitive)
	branches := []struct {
		label string
		token string
	}{
		{"AUTO-REMEDIATE branch", "auto-remediate"},
		{"REQUEST-APPROVAL branch", "request-approval"},
		{"INSTRUCT-OPERATOR branch", "instruct-operator"},
		{"NO-ACTION-AVAILABLE branch", "no-action-available"},
	}
	for _, b := range branches {
		if !strings.Contains(lower, strings.ToLower(b.token)) {
			t.Errorf("agents/escalate/POST.md: missing branch %q — expected label %q", b.label, b.token)
		}
	}

	// Branch selection logic: list-actions must be the selector
	if !strings.Contains(lower, "list-actions") {
		t.Errorf("agents/escalate/POST.md: missing 'list-actions' — branch selection must start with list-actions call")
	}

	// action_class enum values must be present
	actionClasses := []string{"auto-safe", "needs-approval", "informational", "ambiguous"}
	for _, ac := range actionClasses {
		if !strings.Contains(lower, ac) {
			t.Errorf("agents/escalate/POST.md: missing action_class value %q — branch selection must reference all action classes", ac)
		}
	}

	// Required tools for each branch
	branchTools := []string{
		"remediate-action",
		"message-operator",
		"resolve-finding",
		"annotate-finding",
	}
	for _, bt := range branchTools {
		if !strings.Contains(lower, bt) {
			t.Errorf("agents/escalate/POST.md: missing tool %q — required for branch execution", bt)
		}
	}

	// Gate semantics for branch 2
	if !strings.Contains(lower, "gate") {
		t.Errorf("agents/escalate/POST.md: missing 'gate' semantics — branch 2 (REQUEST-APPROVAL) must use cf gate await mechanism")
	}

	// Security injection defense
	if !strings.Contains(content, "USER_DATA_BEGIN") {
		t.Errorf("agents/escalate/POST.md: missing security section with USER_DATA_BEGIN marker")
	}
	if !strings.Contains(content, "USER_DATA_END") {
		t.Errorf("agents/escalate/POST.md: missing security section with USER_DATA_END marker")
	}

	// Negative assertions: escalate is TERMINAL — must NOT have escalation chain tools
	// These tools would create a cycle or pass work further downstream.
	forbiddenTools := []string{
		"escalate-to-investigator",
		"escalate-to-stage-c",
		"escalate-to-deep",
		"create-investigate-merge",
		"write-partial-transcript",
		"load-skill",
		"approve-action",
	}
	for _, ft := range forbiddenTools {
		if strings.Contains(lower, ft) {
			t.Errorf("agents/escalate/POST.md: forbidden tool %q present — escalate is the terminal stage; no escalation-chain tools allowed", ft)
		}
	}
}

// TestMallcopPromptExists verifies that agents/mallcop/POST.md exists and contains
// the key directives required by F3B: ported interactive agent capabilities,
// §Approval Gate Handling (with HARD INVARIANT against auto-approval), and
// §Routing Operator-Initiated Investigations.
func TestMallcopPromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "mallcop", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create agents/mallcop/POST.md (F3B)", promptPath, err)
	}
	content := string(data)
	lower := strings.ToLower(content)

	// ---- Positive: ported interactive agent capabilities ----

	// Core tool references from the interactive Python source
	coreTools := []struct {
		label string
		token string
	}{
		{"list-findings tool", "list-findings"},
		{"read-finding tool", "read-finding"},
		{"search-events tool", "search-events"},
		{"annotate-finding tool", "annotate-finding"},
		{"escalate-to-investigator tool", "escalate-to-investigator"},
	}
	for _, ct := range coreTools {
		if !strings.Contains(lower, strings.ToLower(ct.token)) {
			t.Errorf("agents/mallcop/POST.md: missing %s (%q) — must be ported from interactive source", ct.label, ct.token)
		}
	}

	// Security injection defense section (must be present from the port)
	if !strings.Contains(content, "USER_DATA_BEGIN") {
		t.Errorf("agents/mallcop/POST.md: missing security section with USER_DATA_BEGIN marker")
	}
	if !strings.Contains(content, "USER_DATA_END") {
		t.Errorf("agents/mallcop/POST.md: missing security section with USER_DATA_END marker")
	}

	// ---- Positive: §Approval Gate Handling section ----

	if !strings.Contains(content, "§Approval Gate Handling") && !strings.Contains(lower, "approval gate handling") {
		t.Errorf("agents/mallcop/POST.md: missing §Approval Gate Handling section")
	}

	// Approval gate steps: read-finding must be called to fetch finding context
	if !strings.Contains(lower, "read-finding") {
		t.Errorf("agents/mallcop/POST.md: missing read-finding in approval gate — agent must fetch finding context before prompting operator")
	}

	// approve-action must be referenced (it's the tool called after explicit approval)
	if !strings.Contains(lower, "approve-action") {
		t.Errorf("agents/mallcop/POST.md: missing approve-action reference — approval gate handling must document the approve-action call")
	}

	// Approval gate must specify gate_id, verdict, and operator_reason fields
	gateCalls := []struct {
		label string
		token string
	}{
		{"gate_id parameter", "gate_id"},
		{"verdict parameter", "verdict"},
		{"operator_reason parameter", "operator_reason"},
	}
	for _, gc := range gateCalls {
		if !strings.Contains(lower, strings.ToLower(gc.token)) {
			t.Errorf("agents/mallcop/POST.md: missing approve-action parameter %q in §Approval Gate Handling", gc.label)
		}
	}

	// Must state that operator's exact words are passed as operator_reason
	if !strings.Contains(lower, "exact words") && !strings.Contains(lower, "their words") && !strings.Contains(lower, "their exact") {
		t.Errorf("agents/mallcop/POST.md: §Approval Gate Handling must state that operator's exact words are passed as operator_reason")
	}

	// Must require operator waits (explicit human response before approve-action)
	waitTokens := []string{"wait", "explicit"}
	hasWait := false
	for _, w := range waitTokens {
		if strings.Contains(lower, w) {
			hasWait = true
			break
		}
	}
	if !hasWait {
		t.Errorf("agents/mallcop/POST.md: §Approval Gate Handling must use explicit wait-for-operator language")
	}

	// HARD INVARIANT: must contain explicit prohibition language about auto-approval
	// Check for the "MUST NEVER" or equivalent prohibition language
	prohibitionPhrases := []string{
		"must never call approve-action",
		"must never call `approve-action`",
		"never auto-approve",
		"never call approve-action without",
		"must not call approve-action",
	}
	hasProhibition := false
	for _, p := range prohibitionPhrases {
		if strings.Contains(lower, strings.ToLower(p)) {
			hasProhibition = true
			break
		}
	}
	if !hasProhibition {
		t.Errorf("agents/mallcop/POST.md: §Approval Gate Handling must contain explicit MUST NEVER prohibition for approve-action without human approval")
	}

	// Must explicitly address injection attacks (adversarial content in finding metadata)
	injectionTokens := []string{"injection", "adversarial", "untrusted"}
	hasInjectionDefense := false
	for _, tok := range injectionTokens {
		if strings.Contains(lower, tok) {
			hasInjectionDefense = true
			break
		}
	}
	if !hasInjectionDefense {
		t.Errorf("agents/mallcop/POST.md: §Approval Gate Handling must address prompt-injection attacks from finding metadata")
	}

	// ---- Positive: §Routing Operator-Initiated Investigations section ----

	if !strings.Contains(content, "§Routing Operator-Initiated Investigations") &&
		!strings.Contains(lower, "routing operator-initiated investigations") {
		t.Errorf("agents/mallcop/POST.md: missing §Routing Operator-Initiated Investigations section")
	}

	// investigate <finding-id> pattern must be mentioned
	if !strings.Contains(lower, "investigate") {
		t.Errorf("agents/mallcop/POST.md: §Routing must mention 'investigate <finding-id>' trigger pattern")
	}

	// escalate-to-investigator must be called with operator-initiated reason
	if !strings.Contains(lower, "operator-initiated") {
		t.Errorf("agents/mallcop/POST.md: §Routing must specify reason='operator-initiated' when calling escalate-to-investigator")
	}

	// ---- Negative: approve-action MUST NOT be called automatically ----
	// Search for forbidden phrasing in the approval-gate section.
	// "auto-approve" without a negation nearby is a hard fail.
	// We check for the raw token "auto-approve" — if present, context must negate it.
	autoApproveIdx := strings.Index(lower, "auto-approve")
	if autoApproveIdx >= 0 {
		// Extract surrounding context (150 chars each side) to check for negation
		start := autoApproveIdx - 150
		if start < 0 {
			start = 0
		}
		end := autoApproveIdx + len("auto-approve") + 150
		if end > len(lower) {
			end = len(lower)
		}
		ctx := lower[start:end]

		// If the context contains negation keywords, it's fine (the spec is saying NOT to do it)
		negationKeywords := []string{"never", "not", "must not", "no auto", "do not", "prohibit", "forbidden"}
		hasNegation := false
		for _, neg := range negationKeywords {
			if strings.Contains(ctx, neg) {
				hasNegation = true
				break
			}
		}
		if !hasNegation {
			t.Errorf("agents/mallcop/POST.md: found 'auto-approve' without negation in surrounding context — approval section must NEVER authorize automatic approval; if 'auto-approve' appears, it must be explicitly negated")
		}
	}

	// ---- Negative: smoke fixture files must exist ----
	smokeFixtures := []struct {
		name string
		path string
	}{
		{"smoke-mallcop-list", filepath.Join(root, "docs", "academy", "smoke-mallcop-list.json")},
		{"smoke-mallcop-approve", filepath.Join(root, "docs", "academy", "smoke-mallcop-approve.json")},
		{"smoke-mallcop-injection", filepath.Join(root, "docs", "academy", "smoke-mallcop-injection.json")},
	}
	for _, fix := range smokeFixtures {
		if _, err := os.Stat(fix.path); err != nil {
			t.Errorf("missing smoke fixture %s at %s — F3B requires all 3 smoke fixtures documented", fix.name, fix.path)
		} else {
			// Must be valid JSON
			fixData, readErr := os.ReadFile(fix.path)
			if readErr != nil {
				t.Errorf("cannot read smoke fixture %s: %v", fix.name, readErr)
			} else {
				var doc map[string]interface{}
				if jsonErr := json.Unmarshal(fixData, &doc); jsonErr != nil {
					t.Errorf("smoke fixture %s is not valid JSON: %v", fix.name, jsonErr)
				} else {
					// Must have fixture_id and description
					for _, field := range []string{"fixture_id", "description", "prerequisites"} {
						if _, ok := doc[field]; !ok {
							t.Errorf("smoke fixture %s: missing required field %q", fix.name, field)
						}
					}
				}
			}
		}
	}
}

// TestEscalateSmokeFixturesWellFormed verifies that all 4 escalate branch smoke
// fixtures exist and have the required shape: finding_id, branch, list_actions_response,
// expected_operator_artifact, and expected_verdict.
func TestEscalateSmokeFixturesWellFormed(t *testing.T) {
	root := repoRoot(t)

	fixtures := []struct {
		name   string
		path   string
		branch string
	}{
		{
			name:   "smoke-escalate-auto-safe",
			path:   filepath.Join(root, "docs", "academy", "smoke-escalate-auto-safe.json"),
			branch: "AUTO-REMEDIATE",
		},
		{
			name:   "smoke-escalate-approval",
			path:   filepath.Join(root, "docs", "academy", "smoke-escalate-approval.json"),
			branch: "REQUEST-APPROVAL",
		},
		{
			name:   "smoke-escalate-instruct",
			path:   filepath.Join(root, "docs", "academy", "smoke-escalate-instruct.json"),
			branch: "INSTRUCT-OPERATOR",
		},
		{
			name:   "smoke-escalate-no-action",
			path:   filepath.Join(root, "docs", "academy", "smoke-escalate-no-action.json"),
			branch: "NO-ACTION-AVAILABLE",
		},
	}

	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			data, err := os.ReadFile(fix.path)
			if err != nil {
				t.Fatalf("fixture file missing: %s: %v", fix.path, err)
			}

			var doc map[string]interface{}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("fixture %s is not valid JSON: %v", fix.name, err)
			}

			// Must have finding_id nested in finding object
			findingObj, ok := doc["finding"].(map[string]interface{})
			if !ok {
				t.Errorf("fixture %s: missing 'finding' object", fix.name)
			} else {
				if _, ok := findingObj["finding_id"]; !ok {
					t.Errorf("fixture %s: missing finding.finding_id", fix.name)
				}
			}

			// Must have branch matching expected
			branch, _ := doc["branch"].(string)
			if branch != fix.branch {
				t.Errorf("fixture %s: branch=%q, want %q", fix.name, branch, fix.branch)
			}

			// Must have list_actions_response (may be empty array for branch 3/4)
			if _, ok := doc["list_actions_response"]; !ok {
				t.Errorf("fixture %s: missing 'list_actions_response'", fix.name)
			}

			// Must have expected_operator_artifact
			artifact, ok := doc["expected_operator_artifact"].(map[string]interface{})
			if !ok {
				t.Errorf("fixture %s: missing 'expected_operator_artifact' object", fix.name)
			} else {
				// Must specify tool and type
				for _, field := range []string{"type", "tool"} {
					if _, ok := artifact[field]; !ok {
						t.Errorf("fixture %s: expected_operator_artifact missing field %q", fix.name, field)
					}
				}
			}

			// Must have expected_verdict
			verdict, ok := doc["expected_verdict"].(map[string]interface{})
			if !ok {
				t.Errorf("fixture %s: missing 'expected_verdict' object", fix.name)
			} else {
				// Must have resolve_action or action
				hasAction := false
				if _, ok := verdict["action"]; ok {
					hasAction = true
				}
				if _, ok := verdict["resolve_action"]; ok {
					hasAction = true
				}
				if !hasAction {
					t.Errorf("fixture %s: expected_verdict missing 'action' or 'resolve_action'", fix.name)
				}
			}
		})
	}
}
