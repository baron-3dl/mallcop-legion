package quality_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from the test file location.
// The test lives at test/quality/, two levels below the repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// filename = .../test/quality/judge_prompt_lint_test.go
	// go up two directories to reach repo root
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

// TestJudgePromptLint asserts that agents/judge/POST.md:
//  1. Does not contain any forbidden taxonomy strings (whole-word, case-insensitive).
//  2. Contains all required rubric field names.
func TestJudgePromptLint(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "judge", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", promptPath, err)
	}
	content := string(data)

	// -------------------------------------------------------------------------
	// A) Forbidden substrings — taxonomy codes and scenario-specific language
	// -------------------------------------------------------------------------
	type forbidden struct {
		label   string
		pattern string
	}

	// Taxonomy codes are two-letter uppercase codes used as whole words.
	// We use \b word-boundaries so "kafka", "aka", "vnd", etc. are NOT matched.
	// Literal strings are matched case-insensitively.
	forbiddenList := []forbidden{
		// Taxonomy codes (whole words, case-insensitive)
		{label: "taxonomy code KA", pattern: `(?i)\bKA\b`},
		{label: "taxonomy code AE", pattern: `(?i)\bAE\b`},
		{label: "taxonomy code CS", pattern: `(?i)\bCS\b`},
		{label: "taxonomy code NE", pattern: `(?i)\bNE\b`},
		{label: "taxonomy code VN", pattern: `(?i)\bVN\b`},
		{label: "taxonomy code TT", pattern: `(?i)\bTT\b`},
		// Scenario category labels
		{label: "known-actor",            pattern: `(?i)known[-\s]actor`},
		{label: "known actor abuse",      pattern: `(?i)known\s+actor\s+abuse`},
		{label: "new-entity",             pattern: `(?i)new[-\s]entity`},
		{label: "automated execution",    pattern: `(?i)automated\s+execution`},
		{label: "credential sharing",     pattern: `(?i)credential\s+sharing`},
		{label: "credential abuse",       pattern: `(?i)credential\s+abuse`},
		{label: "volume anomaly",         pattern: `(?i)volume\s+anomaly`},
		{label: "timing trap",            pattern: `(?i)timing\s+trap`},
		// Scenario template field names
		{label: "trap_description",       pattern: `(?i)trap_description`},
		{label: "trap_resolved_means",    pattern: `(?i)trap_resolved_means`},
		{label: "expected_resolution",    pattern: `(?i)expected_resolution`},
	}

	var failures []string

	for _, f := range forbiddenList {
		re, err := regexp.Compile(f.pattern)
		if err != nil {
			t.Fatalf("invalid pattern %q for %q: %v", f.pattern, f.label, err)
		}
		if re.MatchString(content) {
			match := re.FindString(content)
			failures = append(failures, fmt.Sprintf("FORBIDDEN %q found (matched %q) — remove taxonomy/scenario language from the judge prompt", f.label, match))
		}
	}

	// -------------------------------------------------------------------------
	// B) Required rubric field names — must appear in the prompt
	// -------------------------------------------------------------------------
	required := []string{
		"finding_id",
		"verdict",
		"reasoning_quality",
		"investigation_thoroughness",
		"resolve_quality",
		"escalation_actionability",
		"rationale",
		"fix_target",
	}

	lower := strings.ToLower(content)
	for _, field := range required {
		if !strings.Contains(lower, strings.ToLower(field)) {
			failures = append(failures, fmt.Sprintf("MISSING required rubric field %q — add it to agents/judge/POST.md", field))
		}
	}

	// -------------------------------------------------------------------------
	// Report all failures at once
	// -------------------------------------------------------------------------
	if len(failures) > 0 {
		t.Errorf("agents/judge/POST.md lint failed with %d issue(s):", len(failures))
		for _, msg := range failures {
			t.Errorf("  • %s", msg)
		}
	}
}
