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
		// Scenario category labels — separators now include space, hyphen, and underscore
		{label: "known-actor",             pattern: `(?i)known[_\s-]actor`},
		{label: "known actor abuse",       pattern: `(?i)known[_\s-]actor[_\s-]abuse`},
		{label: "new-entity",              pattern: `(?i)new[_\s-]entity`},
		{label: "automated execution",     pattern: `(?i)automated[_\s-]execution`},
		{label: "credential sharing",      pattern: `(?i)credential[_\s-]sharing`},
		{label: "credential abuse",        pattern: `(?i)credential[_\s-]abuse`},
		{label: "credential theft",        pattern: `(?i)credential[_\s-]theft`},
		{label: "volume anomaly",          pattern: `(?i)volume[_\s-]anomaly`},
		{label: "timing trap",             pattern: `(?i)timing[_\s-]trap`},
		// Scenario template field names
		{label: "trap_description",        pattern: `(?i)trap_description`},
		{label: "trap_resolved_means",     pattern: `(?i)trap_resolved_means`},
		{label: "expected_resolution",     pattern: `(?i)expected_resolution`},
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

// TestForbiddenPatternsActuallyFire verifies that each widened pattern
// correctly matches space, hyphen, and underscore separators.
// This prevents accidentally widening the net in a way that still misses variants.
func TestForbiddenPatternsActuallyFire(t *testing.T) {
	testCases := []struct {
		pattern string
		input   string
		label   string
	}{
		// Test underscore variants of multi-word patterns
		{pattern: `(?i)known[_\s-]actor`, input: "known_actor", label: "known_actor"},
		{pattern: `(?i)known[_\s-]actor[_\s-]abuse`, input: "known_actor_abuse", label: "known_actor_abuse"},
		{pattern: `(?i)new[_\s-]entity`, input: "new_entity", label: "new_entity"},
		{pattern: `(?i)automated[_\s-]execution`, input: "automated_execution", label: "automated_execution"},
		{pattern: `(?i)credential[_\s-]sharing`, input: "credential_sharing", label: "credential_sharing"},
		{pattern: `(?i)credential[_\s-]abuse`, input: "credential_abuse", label: "credential_abuse"},
		{pattern: `(?i)credential[_\s-]theft`, input: "credential_theft", label: "credential_theft"},
		{pattern: `(?i)volume[_\s-]anomaly`, input: "volume_anomaly", label: "volume_anomaly"},
		{pattern: `(?i)timing[_\s-]trap`, input: "timing_trap", label: "timing_trap"},
		// Test hyphen variants
		{pattern: `(?i)known[_\s-]actor`, input: "known-actor", label: "known-actor"},
		{pattern: `(?i)credential[_\s-]sharing`, input: "credential-sharing", label: "credential-sharing"},
		// Test space variants (original form should still work)
		{pattern: `(?i)volume[_\s-]anomaly`, input: "volume anomaly", label: "volume anomaly (space)"},
	}

	for _, tc := range testCases {
		t.Run(tc.label, func(t *testing.T) {
			re, err := regexp.Compile(tc.pattern)
			if err != nil {
				t.Fatalf("invalid pattern %q: %v", tc.pattern, err)
			}
			if !re.MatchString(tc.input) {
				t.Errorf("pattern %q did not match input %q", tc.pattern, tc.input)
			}
		})
	}
}
