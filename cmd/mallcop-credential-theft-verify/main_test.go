package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireCF skips the test if cf is not on PATH.
func requireCF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping campfire integration tests")
	}
	return p
}

// newIsolatedCampfire initialises a fresh cf home and creates a campfire.
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

	createCmd := exec.Command(cfBin, "create", "--description", "test-ctt-"+t.Name())
	createCmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := createCmd.Output()
	if err != nil {
		t.Fatalf("cf create: %v\n%s", err, out)
	}

	campfireID := ""
	for _, line := range splitLines(string(out)) {
		if len(line) == 64 && isHex(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from cf create output:\n%s", out)
	}
	return cfHome, campfireID
}

// sendCTT posts a credential-theft-test:considered message to the campfire.
func sendCTT(t *testing.T, cfBin, cfHome, campfireID string, body interface{}) {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	cmd := exec.Command(cfBin, "send", campfireID, string(payload), "--tag", "credential-theft-test:considered")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send: %v\n%s", err, out)
	}
}

// buildVerifyBinary compiles mallcop-credential-theft-verify into a temp dir.
func buildVerifyBinary(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}

	bin := filepath.Join(t.TempDir(), "mallcop-credential-theft-verify")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop-credential-theft-verify")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mallcop-credential-theft-verify: %v\n%s", err, out)
	}
	return bin
}

// runVerify invokes the binary with the given campfireID and returns (exitCode, stderr).
func runVerify(t *testing.T, bin, cfHome, campfireID string) (int, string) {
	t.Helper()

	cmd := exec.Command(bin)
	cmd.Env = setEnv(setEnv(os.Environ(), "CF_HOME", cfHome), "MALLCOP_CAMPFIRE_ID", campfireID)

	out, err := cmd.CombinedOutput()
	stderr := string(out)

	if err == nil {
		return 0, stderr
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderr
	}
	t.Fatalf("unexpected exec error: %v", err)
	return -1, ""
}

// ---------------------------------------------------------------------------
// Unit tests for validateBody (no campfire needed)
// ---------------------------------------------------------------------------

func TestValidateBody_HappyPath(t *testing.T) {
	body := `{"event_ids":["E1","E2"],"note":"Source IP and device fingerprint are consistent across all sessions and match the expected legitimate user pattern."}`
	if err := validateBody(body); err != nil {
		t.Errorf("expected pass, got: %v", err)
	}
}

func TestValidateBody_EmptyEventIDs(t *testing.T) {
	body := `{"event_ids":[],"note":"nothing found"}`
	if err := validateBody(body); err == nil {
		t.Error("expected failure for empty event_ids, got nil")
	}
}

func TestValidateBody_VacuousNote_Short(t *testing.T) {
	body := `{"event_ids":["E1"],"note":"n/a"}`
	if err := validateBody(body); err == nil {
		t.Error("expected failure for vacuous short note, got nil")
	}
}

func TestValidateBody_MalformedJSON(t *testing.T) {
	body := `not-valid-json`
	if err := validateBody(body); err == nil {
		t.Error("expected failure for malformed JSON, got nil")
	}
}

func TestValidateBody_NoteExactly40Chars(t *testing.T) {
	// Exactly 40 chars — boundary pass
	note := "1234567890123456789012345678901234567890"
	if len(note) != 40 {
		t.Fatalf("note length sanity check: got %d", len(note))
	}
	body, _ := json.Marshal(map[string]interface{}{
		"event_ids": []string{"E1"},
		"note":      note,
	})
	if err := validateBody(string(body)); err != nil {
		t.Errorf("expected pass at boundary 40 chars, got: %v", err)
	}
}

func TestValidateBody_NoteJust39Chars(t *testing.T) {
	// 39 chars — below boundary, should reject
	note := "123456789012345678901234567890123456789"
	if len(note) != 39 {
		t.Fatalf("note length sanity check: got %d", len(note))
	}
	body, _ := json.Marshal(map[string]interface{}{
		"event_ids": []string{"E1"},
		"note":      note,
	})
	if err := validateBody(string(body)); err == nil {
		t.Error("expected failure at 39 chars (below 40 boundary), got nil")
	}
}

// ---------------------------------------------------------------------------
// Integration tests — real campfire, build binary, exercise end-to-end
// ---------------------------------------------------------------------------

func TestIntegration_HappyPath(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	sendCTT(t, cfBin, cfHome, campfireID, map[string]interface{}{
		"event_ids": []string{"evt-login-001", "evt-access-002"},
		"note":      "Source IP and device fingerprint remain consistent across all sessions; only the legitimate user would have this pattern of access correlated with physical office entry.",
	})

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code != 0 {
		t.Errorf("expected exit 0 on happy path, got %d; stderr: %s", code, stderr)
	}
}

func TestIntegration_MessageMissing(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Post a message with a DIFFERENT tag — should not count
	cmd := exec.Command(cfBin, "send", campfireID, `{"event_ids":["E1"],"note":"something"}`, "--tag", "other:tag")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send: %v\n%s", err, out)
	}

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code == 0 {
		t.Errorf("expected non-zero exit when message missing, got 0")
	}
	if stderr == "" {
		t.Error("expected stderr to identify missing message")
	}
	t.Logf("stderr: %s", stderr)
}

func TestIntegration_EventIDsEmpty(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	sendCTT(t, cfBin, cfHome, campfireID, map[string]interface{}{
		"event_ids": []string{},
		"note":      "nothing found here to distinguish anything",
	})

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code == 0 {
		t.Errorf("expected non-zero exit for empty event_ids, got 0")
	}
	t.Logf("stderr: %s", stderr)
}

func TestIntegration_VacuousDistinguishText(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	sendCTT(t, cfBin, cfHome, campfireID, map[string]interface{}{
		"event_ids": []string{"E1"},
		"note":      "n/a",
	})

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code == 0 {
		t.Errorf("expected non-zero exit for vacuous distinguish text, got 0")
	}
	t.Logf("stderr: %s", stderr)
}

func TestIntegration_MalformedJSON(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Post a non-JSON payload with the correct tag
	cmd := exec.Command(cfBin, "send", campfireID, "not-valid-json", "--tag", "credential-theft-test:considered")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send: %v\n%s", err, out)
	}

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code == 0 {
		t.Errorf("expected non-zero exit for malformed JSON body, got 0")
	}
	t.Logf("stderr: %s", stderr)
}

func TestIntegration_WrongTagCase(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildVerifyBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Post with wrong-case tag — should not be found
	cmd := exec.Command(cfBin, "send", campfireID,
		`{"event_ids":["E1"],"note":"Source IP and device fingerprint are consistent across all sessions with legitimate pattern."}`,
		"--tag", "credential-theft-test:Considered")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send: %v\n%s", err, out)
	}

	code, stderr := runVerify(t, bin, cfHome, campfireID)
	if code == 0 {
		t.Errorf("expected non-zero exit for wrong tag case, got 0")
	}
	t.Logf("stderr: %s", stderr)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func setEnv(base []string, key, val string) []string {
	prefix := key + "="
	result := make([]string, 0, len(base)+1)
	for _, e := range base {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			continue
		}
		result = append(result, e)
	}
	return append(result, key+"="+val)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, trimSpaceStr(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, trimSpaceStr(s[start:]))
	}
	return lines
}

func trimSpaceStr(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
