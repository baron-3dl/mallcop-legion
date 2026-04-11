// Tests for mallcop-checklist-verify.
//
// Unit tests exercise verifyChecklist directly against in-process message fixtures.
// They cover all 7 rule failure modes specified in the item description.
//
// Integration test (build tag: hookintegration):
//   - legion's HookEngine does not currently invoke external command binaries
//     (the `command=` field in HookConfig is a scaffolded but unimplemented feature;
//     see legion/internal/automaton/hooks.go and docs/spikes/workcontext-external.md §Gap 4).
//   - The integration test therefore spawns the binary directly against a real
//     isolated campfire (cf init + cf send + binary invocation), which validates
//     the full execution path including campfire reads.
//   - A followup item should be filed requesting legion expose a
//     TestHookEngine helper that supports command-type hooks once G2 is
//     implemented upstream. Until then, the binary-spawn path is the correct
//     end-to-end test.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeMsg constructs a cfMessage with the given item number and body.
func makeMsg(itemN int, body string) cfMessage {
	return cfMessage{
		ID:      "msg-" + strconv.Itoa(itemN),
		Payload: body,
		Tags:    []string{"checklist:item:" + strconv.Itoa(itemN)},
	}
}

// allItems builds a slice of N well-formed checklist messages (items 1..N).
// Each body contains a transcript:line reference so evidence citations pass.
func allItems(n int) []cfMessage {
	msgs := make([]cfMessage, n)
	for i := 1; i <= n; i++ {
		msgs[i-1] = makeMsg(i, "Analysis complete. See transcript:line-"+strconv.Itoa(i*10)+" for details.")
	}
	return msgs
}

// ---------------------------------------------------------------------------
// Unit tests: verifyChecklist
// ---------------------------------------------------------------------------

// Test 1: all 5 items present, non-empty, evidence cited → pass.
func TestVerifyChecklist_AllFivePresentWithEvidence(t *testing.T) {
	msgs := allItems(5)
	if err := verifyChecklist(msgs, 5, "bead-001"); err != nil {
		t.Errorf("expected pass, got error: %v", err)
	}
}

// Test 2: missing item 3 → fail identifying item 3.
func TestVerifyChecklist_MissingItem3(t *testing.T) {
	msgs := allItems(5)
	// Drop item 3.
	filtered := msgs[:2:2]
	filtered = append(filtered, msgs[3:]...)

	err := verifyChecklist(filtered, 5, "bead-002")
	if err == nil {
		t.Fatal("expected error for missing item 3, got nil")
	}
	if !strings.Contains(err.Error(), "checklist:item:3") {
		t.Errorf("error should mention checklist:item:3, got: %v", err)
	}
	// Items 1,2,4,5 should not appear in the failure list.
	for _, ok := range []string{"checklist:item:1", "checklist:item:2", "checklist:item:4", "checklist:item:5"} {
		if strings.Contains(err.Error(), ok+" missing") || strings.Contains(err.Error(), ok+" present but") {
			t.Errorf("unexpected failure mention of %s: %v", ok, err)
		}
	}
}

// Test 3: item 2 present but body is empty → fail identifying item 2.
func TestVerifyChecklist_Item2EmptyBody(t *testing.T) {
	msgs := allItems(5)
	msgs[1] = makeMsg(2, "   ") // whitespace-only

	err := verifyChecklist(msgs, 5, "bead-003")
	if err == nil {
		t.Fatal("expected error for empty body on item 2, got nil")
	}
	if !strings.Contains(err.Error(), "checklist:item:2") {
		t.Errorf("error should mention checklist:item:2, got: %v", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should say 'empty', got: %v", err)
	}
}

// Test 4: item 4 present but body has no evidence citation → fail identifying item 4.
func TestVerifyChecklist_Item4NoEvidenceCitation(t *testing.T) {
	msgs := allItems(5)
	msgs[3] = makeMsg(4, "This looks suspicious based on general principles.")

	err := verifyChecklist(msgs, 5, "bead-004")
	if err == nil {
		t.Fatal("expected error for missing evidence citation on item 4, got nil")
	}
	if !strings.Contains(err.Error(), "checklist:item:4") {
		t.Errorf("error should mention checklist:item:4, got: %v", err)
	}
	if !strings.Contains(err.Error(), "evidence citation") {
		t.Errorf("error should mention 'evidence citation', got: %v", err)
	}
}

// Test 5: malformed tag (checklist:item:six) → tag not parsed as valid item number,
// item 6 treated as missing when count=6.
func TestVerifyChecklist_MalformedTag(t *testing.T) {
	msgs := allItems(5)
	// Add a message with a malformed item tag.
	malformed := cfMessage{
		ID:      "msg-bad",
		Payload: "body with evidence: event:evt-abc123",
		Tags:    []string{"checklist:item:six"},
	}
	msgs = append(msgs, malformed)

	// With count=6, item 6 should be missing (malformed tag is ignored).
	err := verifyChecklist(msgs, 6, "bead-005")
	if err == nil {
		t.Fatal("expected error for missing item 6 (malformed tag), got nil")
	}
	if !strings.Contains(err.Error(), "checklist:item:6") {
		t.Errorf("error should mention checklist:item:6 missing, got: %v", err)
	}
}

// Test 6: all 7 items present (investigate disposition) → pass.
func TestVerifyChecklist_AllSevenPresentInvestigate(t *testing.T) {
	msgs := allItems(7)
	if err := verifyChecklist(msgs, 7, "bead-006"); err != nil {
		t.Errorf("expected pass for 7/7 items, got error: %v", err)
	}
}

// Test 7: 6 of 7 items present → fail.
func TestVerifyChecklist_SixOfSevenFails(t *testing.T) {
	msgs := allItems(7)
	// Drop item 7.
	msgs = msgs[:6]

	err := verifyChecklist(msgs, 7, "bead-007")
	if err == nil {
		t.Fatal("expected error for 6/7 items, got nil")
	}
	if !strings.Contains(err.Error(), "checklist:item:7") {
		t.Errorf("error should mention checklist:item:7, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Evidence citation regex unit tests
// ---------------------------------------------------------------------------

func TestEvidenceCitationRe_Patterns(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"see transcript:line-42 for details", true},
		{"see event:evt-abc123 for context", true},
		{"see evt-003 in the stream", true},
		{"TRANSCRIPT:LINE-99 uppercase", true},
		{"no citation here at all", false},
		{"checklist:item:3 is not a citation", false},
		{"event: (no id after colon)", false},
		{"transcript:line- (no digits)", false},
	}
	for _, c := range cases {
		got := evidenceCitationRe.MatchString(c.input)
		if got != c.want {
			t.Errorf("evidenceCitationRe.MatchString(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// itemNumber unit tests
// ---------------------------------------------------------------------------

func TestItemNumber(t *testing.T) {
	cases := []struct {
		tag  string
		want int
	}{
		{"checklist:item:1", 1},
		{"checklist:item:7", 7},
		{"checklist:item:10", 10},
		{"checklist:item:six", 0},
		{"checklist:item:", 0},
		{"checklist:item:-1", 0},
		{"checklist:item:0", 0},
		{"other:tag:1", 0},
		{"checklist:item:1:extra", 0},
	}
	for _, c := range cases {
		got := itemNumber(c.tag)
		if got != c.want {
			t.Errorf("itemNumber(%q) = %d, want %d", c.tag, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration test: binary invocation against a real isolated campfire
//
// Build tag: hookintegration (also runs without a tag in standard `go test`
// since we check for cf availability and skip if absent).
//
// This is the load-bearing end-to-end test. It proves:
//  1. The binary builds and runs.
//  2. It reads real campfire messages via `cf read`.
//  3. A complete checklist → exit 0.
//  4. An incomplete checklist → exit 1 with informative stderr.
//
// Note on HookEngine integration:
//   Legion's HookEngine.RunHooks does not invoke external binaries — the
//   `command=` field in HookConfig is scaffolded but unimplemented (see
//   docs/spikes/workcontext-external.md §Gap 4 and legion's convertHooks()
//   which drops Command entirely). The correct integration test is therefore
//   to spawn this binary directly, which is what the exam pipeline will do
//   until G2 is implemented upstream. A followup rd item should request
//   legion expose a testable command-hook path.
// ---------------------------------------------------------------------------

// requireBinary skips the test if the named binary is not on PATH.
func requireBinary(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s binary not found on PATH — skipping integration test", name)
	}
	return p
}

// setEnv returns a copy of environ with key=val set.
func setEnv(environ []string, key, val string) []string {
	prefix := key + "="
	for i, e := range environ {
		if strings.HasPrefix(e, prefix) {
			out := make([]string, len(environ))
			copy(out, environ)
			out[i] = prefix + val
			return out
		}
	}
	return append(environ, prefix+val)
}

// newIsolatedCampfire initialises a fresh cf home and campfire.
// Returns (cfHome, campfireID).
func newIsolatedCampfire(t *testing.T, cfBin string) (string, string) {
	t.Helper()
	cfHome := t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	initCmd := exec.Command(cfBin, "init")
	initCmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	createCmd := exec.Command(cfBin, "create", "--description", "test-checklist-verify-"+t.Name())
	createCmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := createCmd.Output()
	if err != nil {
		t.Fatalf("cf create: %v", err)
	}
	campfireID := parseCampfireID(string(out))
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from cf create output:\n%s", out)
	}
	return cfHome, campfireID
}

// parseCampfireID extracts a 64-hex-char campfire ID from cf create output.
func parseCampfireID(out string) string {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHex(line) {
			return line
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// cfSend sends a message with the given tag to campfire.
func cfSend(t *testing.T, cfBin, cfHome, campfireID, payload, tag string) {
	t.Helper()
	cmd := exec.Command(cfBin, "send", campfireID, payload, "--tag", tag)
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send --tag %s: %v\n%s", tag, err, out)
	}
}

// buildBinary compiles mallcop-checklist-verify into a temp directory.
// Returns the path to the built binary.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mallcop-checklist-verify")

	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "." // must run in cmd/mallcop-checklist-verify
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// TestChecklistVerify_Integration exercises the binary against a real campfire.
func TestChecklistVerify_Integration(t *testing.T) {
	cfBin := requireBinary(t, "cf")
	bin := buildBinary(t)

	t.Run("positive_5_of_5", func(t *testing.T) {
		cfHome, campfireID := newIsolatedCampfire(t, cfBin)

		// Seed 5 valid checklist items.
		for i := 1; i <= 5; i++ {
			body := "Item " + strconv.Itoa(i) + " complete. Evidence at transcript:line-" + strconv.Itoa(i*10) + "."
			cfSend(t, cfBin, cfHome, campfireID, body, "checklist:item:"+strconv.Itoa(i))
		}

		cmd := exec.Command(bin,
			"--campfire", campfireID,
			"--bead-id", "test-bead-001",
			"--checklist-count", "5",
		)
		cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit 0 for 5/5 complete checklist, got error: %v\noutput: %s", err, out)
		}
	})

	t.Run("negative_4_of_5_missing_item3", func(t *testing.T) {
		cfHome, campfireID := newIsolatedCampfire(t, cfBin)

		// Seed 4 of 5 items (skip item 3).
		for _, i := range []int{1, 2, 4, 5} {
			body := "Item " + strconv.Itoa(i) + " complete. Evidence at evt-00" + strconv.Itoa(i) + "."
			cfSend(t, cfBin, cfHome, campfireID, body, "checklist:item:"+strconv.Itoa(i))
		}

		cmd := exec.Command(bin,
			"--campfire", campfireID,
			"--bead-id", "test-bead-002",
			"--checklist-count", "5",
		)
		cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
		out, err := cmd.CombinedOutput()

		if err == nil {
			t.Fatal("expected non-zero exit for missing item 3, got exit 0")
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
			}
		}
		if !strings.Contains(string(out), "checklist:item:3") {
			t.Errorf("stderr should mention checklist:item:3, got: %s", out)
		}
	})

	t.Run("positive_7_of_7_investigate", func(t *testing.T) {
		cfHome, campfireID := newIsolatedCampfire(t, cfBin)

		for i := 1; i <= 7; i++ {
			body := "Item " + strconv.Itoa(i) + ". See event:evt-item-" + strconv.Itoa(i) + " for evidence."
			cfSend(t, cfBin, cfHome, campfireID, body, "checklist:item:"+strconv.Itoa(i))
		}

		cmd := exec.Command(bin,
			"--campfire", campfireID,
			"--bead-id", "test-bead-003",
			"--checklist-count", "7",
		)
		cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit 0 for 7/7 complete checklist, got error: %v\noutput: %s", err, out)
		}
	})

	t.Run("negative_no_evidence_citation", func(t *testing.T) {
		cfHome, campfireID := newIsolatedCampfire(t, cfBin)

		// Item 2 has no evidence citation.
		cfSend(t, cfBin, cfHome, campfireID, "Looked at item 1. transcript:line-1", "checklist:item:1")
		cfSend(t, cfBin, cfHome, campfireID, "This item has no concrete evidence reference.", "checklist:item:2")
		for i := 3; i <= 5; i++ {
			body := "Item " + strconv.Itoa(i) + ". evt-00" + strconv.Itoa(i) + " confirmed."
			cfSend(t, cfBin, cfHome, campfireID, body, "checklist:item:"+strconv.Itoa(i))
		}

		cmd := exec.Command(bin,
			"--campfire", campfireID,
			"--bead-id", "test-bead-004",
			"--checklist-count", "5",
		)
		cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
		out, err := cmd.CombinedOutput()

		if err == nil {
			t.Fatal("expected non-zero exit for item 2 missing evidence, got exit 0")
		}
		combined := string(out)
		if !strings.Contains(combined, "checklist:item:2") {
			t.Errorf("stderr should mention checklist:item:2, got: %s", combined)
		}
		if !strings.Contains(combined, "evidence citation") {
			t.Errorf("stderr should mention 'evidence citation', got: %s", combined)
		}
	})
}
