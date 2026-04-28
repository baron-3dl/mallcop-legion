// tools_f1g_test.go — integration tests for F1G action tools.
//
// Each test that exercises campfire side effects creates an isolated campfire
// (fresh CF_HOME + cf init + cf create) and verifies that the expected message
// tag appears via cf read --json --all after invoking the tool.
//
// Tests that require cf skip via requireCF when the binary is unavailable.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireCFF skips the test if cf is not on PATH. (name differs from other pkg)
func requireCFF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping F1G campfire integration tests")
	}
	return p
}

// newTestCampfire creates an isolated cf home + campfire for testing.
// Returns (cfHome, campfireID). The CF_HOME env var is set for the test.
func newTestCampfire(t *testing.T, cfBin string) (cfHome, campfireID string) {
	t.Helper()
	cfHome = t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	initOut, err := runCFCmd(cfBin, cfHome, "init")
	if err != nil {
		t.Fatalf("cf init: %v\nout: %s", err, initOut)
	}

	createOut, err := runCFCmd(cfBin, cfHome, "create", "--description", "test-f1g-"+t.Name())
	if err != nil {
		t.Fatalf("cf create: %v\nout: %s", err, createOut)
	}

	// Extract 64-char hex ID from output.
	for _, line := range strings.Split(strings.TrimSpace(createOut), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHexStr(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from: %s", createOut)
	}
	return cfHome, campfireID
}

// runCFCmd runs cf with the given cfHome and args, returns combined output.
func runCFCmd(cfBin, cfHome string, args ...string) (string, error) {
	cmd := exec.Command(cfBin, args...)
	cmd.Env = setEnvF1G(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// readCampfireMessages reads all messages from campfireID (cf read --json --all).
func readCampfireMessages(t *testing.T, cfBin, cfHome, campfireID string) []map[string]interface{} {
	t.Helper()
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all")
	cmd.Env = setEnvF1G(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("cf read output: %s", out)
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var msgs []map[string]interface{}
	if jsonErr := json.Unmarshal(out, &msgs); jsonErr != nil {
		t.Logf("cf read parse error: %v; raw: %s", jsonErr, out)
		return nil
	}
	return msgs
}

// hasTagInMessages returns true if any message in msgs has the given tag.
func hasTagInMessages(msgs []map[string]interface{}, wantTag string) bool {
	for _, msg := range msgs {
		tagsRaw, ok := msg["tags"]
		if !ok {
			continue
		}
		switch tags := tagsRaw.(type) {
		case []interface{}:
			for _, tag := range tags {
				if s, ok := tag.(string); ok && s == wantTag {
					return true
				}
			}
		case []string:
			for _, tag := range tags {
				if tag == wantTag {
					return true
				}
			}
		}
	}
	return false
}

// setEnvF1G replaces or adds key=val in the base env slice.
func setEnvF1G(base []string, key, val string) []string {
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

func isHexStr(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// runToolWithEnv calls dispatchActionTool with env vars set for the duration.
// Returns whatever error dispatchActionTool returns.
func runToolWithEnv(t *testing.T, tool, inputJSON string, envPairs ...string) error {
	t.Helper()
	// Set env vars for the duration of the call.
	for i := 0; i+1 < len(envPairs); i += 2 {
		t.Setenv(envPairs[i], envPairs[i+1])
	}
	return dispatchActionTool(tool, inputJSON)
}

// ---- F1G-a: resolve-finding ---------------------------------------------------

func TestResolveFinding_InputValidation(t *testing.T) {
	// Missing input.
	err := dispatchActionTool("resolve-finding", "")
	if err == nil || !strings.Contains(err.Error(), "input JSON required") {
		t.Errorf("expected input-required error, got: %v", err)
	}

	// Missing finding_id.
	err = dispatchActionTool("resolve-finding", `{"action":"resolved","reason":"done"}`)
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Errorf("expected finding_id error, got: %v", err)
	}

	// Invalid action.
	err = dispatchActionTool("resolve-finding", `{"finding_id":"fnd-1","action":"unknown","reason":"x"}`)
	if err == nil || !strings.Contains(err.Error(), "action") {
		t.Errorf("expected action error, got: %v", err)
	}

	// Missing reason.
	err = dispatchActionTool("resolve-finding", `{"finding_id":"fnd-1","action":"resolved"}`)
	if err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("expected reason error, got: %v", err)
	}
}

func TestResolveFinding_PostsToCampfire(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "resolve-finding",
			`{"finding_id":"fnd-test-001","action":"resolved","reason":"Normal activity confirmed after cross-checking with ticket system.","confidence":4}`,
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("resolve-finding: unexpected error: %v", err)
		}
	})

	// Verify JSON output.
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-test-001" {
		t.Errorf("finding_id = %v, want fnd-test-001", result["finding_id"])
	}
	if result["action"] != "resolved" {
		t.Errorf("action = %v, want resolved", result["action"])
	}

	// Verify campfire side effect: message with tag work:output.
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "work:output") {
		t.Errorf("expected message with tag 'work:output' in campfire after resolve-finding; got %d messages", len(msgs))
	}
	if !hasTagInMessages(msgs, "action:resolved") {
		t.Errorf("expected message with tag 'action:resolved' in campfire after resolve-finding")
	}
}

// ---- F1G-a: annotate-finding --------------------------------------------------

func TestAnnotateFinding_InputValidation(t *testing.T) {
	err := dispatchActionTool("annotate-finding", "")
	if err == nil || !strings.Contains(err.Error(), "input JSON required") {
		t.Errorf("expected input-required error, got: %v", err)
	}

	err = dispatchActionTool("annotate-finding", `{"note":"something"}`)
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Errorf("expected finding_id error, got: %v", err)
	}

	err = dispatchActionTool("annotate-finding", `{"finding_id":"fnd-1"}`)
	if err == nil || !strings.Contains(err.Error(), "note") {
		t.Errorf("expected note error, got: %v", err)
	}

	// Note too long.
	longNote := strings.Repeat("x", 4097)
	err = dispatchActionTool("annotate-finding",
		`{"finding_id":"fnd-1","note":"`+longNote+`"}`)
	if err == nil || !strings.Contains(err.Error(), "maxLength") {
		t.Errorf("expected maxLength error, got: %v", err)
	}
}

func TestAnnotateFinding_PostsToCampfireWithTag(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, campfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "annotate-finding",
			`{"finding_id":"fnd-ann-001","note":"Reviewed commit history; the push pattern is consistent with release prep workflow."}`,
			"MALLCOP_CAMPFIRE_ID", campfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("annotate-finding: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-ann-001" {
		t.Errorf("finding_id = %v, want fnd-ann-001", result["finding_id"])
	}

	// Critical: tag must be exactly finding:annotation (consumed by F4B).
	msgs := readCampfireMessages(t, cfBin, cfHome, campfireID)
	if !hasTagInMessages(msgs, "finding:annotation") {
		t.Errorf("expected message with tag 'finding:annotation' (exact); got messages: %+v", msgs)
	}
}

// ---- F1G-b: escalate-to-investigator ------------------------------------------

func TestEscalateToInvestigator_InputValidation(t *testing.T) {
	err := dispatchActionTool("escalate-to-investigator", "")
	if err == nil || !strings.Contains(err.Error(), "input JSON required") {
		t.Errorf("expected input-required error, got: %v", err)
	}
	err = dispatchActionTool("escalate-to-investigator", `{"reason":"x"}`)
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Errorf("expected finding_id error, got: %v", err)
	}
	err = dispatchActionTool("escalate-to-investigator", `{"finding_id":"fnd-1"}`)
	if err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("expected reason error, got: %v", err)
	}
}

func TestEscalateToInvestigator_EmitsWorkCreate(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, workCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "escalate-to-investigator",
			`{"finding_id":"fnd-esc-001","reason":"Unusual login pattern detected from new IP; needs investigation.","confidence":3}`,
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"MALLCOP_ITEM_ID", "triage-item-xyz",
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("escalate-to-investigator: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["finding_id"] != "fnd-esc-001" {
		t.Errorf("finding_id = %v, want fnd-esc-001", result["finding_id"])
	}
	if result["skill"] != "task:investigate" {
		t.Errorf("skill = %v, want task:investigate", result["skill"])
	}
	// item_id must be present (caller uses it for chain provenance).
	if result["item_id"] == nil || result["item_id"] == "" {
		t.Errorf("item_id must be non-empty in output; got %v", result["item_id"])
	}

	// Verify work:create message posted to work campfire.
	msgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(msgs, "work:create") {
		t.Errorf("expected work:create message in work campfire; got %d messages", len(msgs))
	}
}

// ---- F1G-b: escalate-to-stage-c -----------------------------------------------

func TestEscalateToStageC_InputValidation(t *testing.T) {
	err := dispatchActionTool("escalate-to-stage-c",
		`{"finding_id":"fnd-1","reason":"x","action_class":"invalid"}`)
	if err == nil || !strings.Contains(err.Error(), "action_class") {
		t.Errorf("expected action_class error, got: %v", err)
	}
}

func TestEscalateToStageC_EmitsWorkCreate(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, workCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "escalate-to-stage-c",
			`{"finding_id":"fnd-sc-001","reason":"Confirmed suspicious — needs action.","action_class":"needs-approval","flags":["high-risk"]}`,
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("escalate-to-stage-c: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result["action_class"] != "needs-approval" {
		t.Errorf("action_class = %v, want needs-approval", result["action_class"])
	}
	if result["skill"] != "task:escalate" {
		t.Errorf("skill = %v, want task:escalate", result["skill"])
	}

	msgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(msgs, "work:create") {
		t.Errorf("expected work:create in campfire; got messages: %v", msgs)
	}
}

// ---- F1G-b: escalate-to-deep --------------------------------------------------

func TestEscalateToDeep_InputValidation(t *testing.T) {
	err := dispatchActionTool("escalate-to-deep",
		`{"finding_id":"fnd-1","hypothesis":"unknown","partial_transcript_path":"/tmp/x"}`)
	if err == nil || !strings.Contains(err.Error(), "hypothesis") {
		t.Errorf("expected hypothesis error, got: %v", err)
	}

	err = dispatchActionTool("escalate-to-deep",
		`{"finding_id":"fnd-1","hypothesis":"benign"}`)
	if err == nil || !strings.Contains(err.Error(), "partial_transcript_path") {
		t.Errorf("expected partial_transcript_path error, got: %v", err)
	}
}

func TestEscalateToDeep_ReturnsItemID(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, workCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "escalate-to-deep",
			`{"finding_id":"fnd-deep-001","hypothesis":"malicious","partial_transcript_path":"/tmp/fnd-deep-001-partial.md"}`,
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("escalate-to-deep: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	// item_id must be returned so callers can chain into create-investigate-merge.
	if result["item_id"] == nil || result["item_id"] == "" {
		t.Errorf("item_id must be non-empty (needed for create-investigate-merge chain)")
	}
	if result["hypothesis"] != "malicious" {
		t.Errorf("hypothesis = %v, want malicious", result["hypothesis"])
	}

	msgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(msgs, "work:create") {
		t.Errorf("expected work:create in campfire after escalate-to-deep")
	}
}

// ---- F1G-b: create-investigate-merge ------------------------------------------

func TestCreateInvestigateMerge_InputValidation(t *testing.T) {
	// Too few deep_item_ids.
	err := dispatchActionTool("create-investigate-merge",
		`{"finding_id":"fnd-1","deep_item_ids":["a","b"]}`)
	if err == nil || !strings.Contains(err.Error(), "exactly 3") {
		t.Errorf("expected exactly-3 error, got: %v", err)
	}

	// Empty item ID in array.
	err = dispatchActionTool("create-investigate-merge",
		`{"finding_id":"fnd-1","deep_item_ids":["a","b",""]}`)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-id error, got: %v", err)
	}
}

func TestCreateInvestigateMerge_EmitsWorkCreateAndWiresDeps(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, workCampfireID := newTestCampfire(t, cfBin)

	// Fake deep item IDs (they don't need to exist in rd for the merge item creation).
	deepIDs := []string{"deep-item-aaa", "deep-item-bbb", "deep-item-ccc"}
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"finding_id":   "fnd-merge-001",
		"deep_item_ids": deepIDs,
	})

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "create-investigate-merge",
			string(inputJSON),
			"MALLCOP_WORK_CAMPFIRE_ID", workCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("create-investigate-merge: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if result["item_id"] == nil || result["item_id"] == "" {
		t.Errorf("item_id must be non-empty in output")
	}
	if result["skill"] != "task:investigate-merge" {
		t.Errorf("skill = %v, want task:investigate-merge", result["skill"])
	}

	msgs := readCampfireMessages(t, cfBin, cfHome, workCampfireID)
	if !hasTagInMessages(msgs, "work:create") {
		t.Errorf("expected work:create in campfire; msgs=%+v", msgs)
	}
}

// ---- F1G-b: write-partial-transcript ------------------------------------------

func TestWritePartialTranscript_InputValidation(t *testing.T) {
	err := dispatchActionTool("write-partial-transcript", `{"content":"something"}`)
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Errorf("expected finding_id error, got: %v", err)
	}

	err = dispatchActionTool("write-partial-transcript", `{"finding_id":"fnd-1"}`)
	if err == nil || !strings.Contains(err.Error(), "content") {
		t.Errorf("expected content error, got: %v", err)
	}
}

func TestWritePartialTranscript_WritesFile(t *testing.T) {
	// Override run dir to a temp location.
	runDir := t.TempDir()
	transcriptBase := filepath.Join(runDir, ".run", "transcripts", "test-run")
	if err := os.MkdirAll(transcriptBase, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	t.Setenv("MALLCOP_RUN_ID", "test-run")

	// We need to override the hardcoded path in the implementation.
	// The implementation uses /home/baron/projects/mallcop-legion/.run/transcripts/<run-id>.
	// For testing, use the actual path since MALLCOP_RUN_ID is set.
	// The test just verifies the file is created at the expected path.
	const content = "# Partial transcript\n\nThis is a test partial transcript for finding fnd-wpt-001."
	inputJSON, _ := json.Marshal(map[string]interface{}{
		"finding_id": "fnd-wpt-001",
		"content":    content,
	})

	out := captureStdout(t, func() {
		err := dispatchActionTool("write-partial-transcript", string(inputJSON))
		if err != nil {
			t.Errorf("write-partial-transcript: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if result["path"] == nil {
		t.Fatal("path must be in output")
	}
	path := result["path"].(string)
	if !strings.HasSuffix(path, "fnd-wpt-001-partial.md") {
		t.Errorf("path = %q, want suffix fnd-wpt-001-partial.md", path)
	}
	// Verify file exists and has correct content.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != content {
		t.Errorf("file content mismatch\ngot:  %q\nwant: %q", string(data), content)
	}
}

// ---- F1G-c: list-actions ------------------------------------------------------

func TestListActions_InputValidation(t *testing.T) {
	err := dispatchActionTool("list-actions", `{}`)
	if err == nil || !strings.Contains(err.Error(), "detector") {
		t.Errorf("expected detector error, got: %v", err)
	}
}

func TestListActions_ReadsRegistry(t *testing.T) {
	// Create a temp registry.
	registryDir := t.TempDir()
	registryPath := filepath.Join(registryDir, "remediation-registry.yaml")
	registryContent := `{
		"version": 1,
		"actions": [
			{
				"action_name": "revoke-collaborator",
				"action_class": "auto-safe",
				"description": "Revoke external collaborator access.",
				"detector": "new-external-access"
			},
			{
				"action_name": "disable-account",
				"action_class": "needs-approval",
				"description": "Disable account pending investigation.",
				"detector": "privilege-escalation"
			}
		]
	}`
	if err := os.WriteFile(registryPath, []byte(registryContent), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	t.Setenv("MALLCOP_REGISTRY_PATH", registryPath)

	out := captureStdout(t, func() {
		err := dispatchActionTool("list-actions",
			`{"detector":"new-external-access"}`)
		if err != nil {
			t.Errorf("list-actions: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	actions, ok := result["actions"].([]interface{})
	if !ok {
		t.Fatalf("actions not an array: %T %v", result["actions"], result["actions"])
	}
	if len(actions) != 1 {
		t.Errorf("want 1 action for new-external-access, got %d", len(actions))
	}
}

func TestListActions_ActionClassFilter(t *testing.T) {
	registryDir := t.TempDir()
	registryPath := filepath.Join(registryDir, "remediation-registry.yaml")
	registryContent := `{
		"version": 1,
		"actions": [
			{"action_name":"a1","action_class":"auto-safe","description":"d1","detector":"det-x"},
			{"action_name":"a2","action_class":"needs-approval","description":"d2","detector":"det-x"}
		]
	}`
	if err := os.WriteFile(registryPath, []byte(registryContent), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	t.Setenv("MALLCOP_REGISTRY_PATH", registryPath)

	out := captureStdout(t, func() {
		err := dispatchActionTool("list-actions",
			`{"detector":"det-x","action_class_filter":"auto-safe"}`)
		if err != nil {
			t.Errorf("list-actions: unexpected error: %v", err)
		}
	})
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}
	actions := result["actions"].([]interface{})
	if len(actions) != 1 {
		t.Errorf("want 1 auto-safe action, got %d", len(actions))
	}
}

// ---- F1G-c: remediate-action --------------------------------------------------

func TestRemediateAction_InputValidation(t *testing.T) {
	err := dispatchActionTool("remediate-action", `{"finding_id":"fnd-1"}`)
	if err == nil || !strings.Contains(err.Error(), "action_name") {
		t.Errorf("expected action_name error, got: %v", err)
	}
}

func TestRemediateAction_PostsActionRecord(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, operatorCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "remediate-action",
			`{"finding_id":"fnd-rem-001","action_name":"revoke-collaborator"}`,
			"MALLCOP_OPERATOR_CAMPFIRE_ID", operatorCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("remediate-action: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if result["receipt_id"] == nil || result["receipt_id"] == "" {
		t.Errorf("receipt_id must be non-empty")
	}
	if result["status"] != "recorded" {
		t.Errorf("status = %v, want recorded", result["status"])
	}

	// Verify campfire: remediation:action-record tag present.
	msgs := readCampfireMessages(t, cfBin, cfHome, operatorCampfireID)
	if !hasTagInMessages(msgs, "remediation:action-record") {
		t.Errorf("expected remediation:action-record tag in operator campfire; msgs=%+v", msgs)
	}
}

// ---- F1G-c: request-approval --------------------------------------------------

func TestRequestApproval_InputValidation(t *testing.T) {
	err := dispatchActionTool("request-approval",
		`{"finding_id":"fnd-1","action_name":"disable-account"}`)
	if err == nil || !strings.Contains(err.Error(), "justification") {
		t.Errorf("expected justification error, got: %v", err)
	}
}

func TestRequestApproval_PostsGateToOperatorCampfire(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, operatorCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "request-approval",
			`{"finding_id":"fnd-gate-001","action_name":"disable-account","justification":"Account shows credential theft indicators; disabling prevents further damage while investigation continues."}`,
			"MALLCOP_OPERATOR_CAMPFIRE_ID", operatorCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("request-approval: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	gateID, _ := result["gate_id"].(string)
	if gateID == "" {
		t.Errorf("gate_id must be non-empty in output; got %v", result["gate_id"])
	}
	if result["status"] != "pending" {
		t.Errorf("status = %v, want pending", result["status"])
	}

	// Verify campfire: approval-request future tag.
	msgs := readCampfireMessages(t, cfBin, cfHome, operatorCampfireID)
	if !hasTagInMessages(msgs, "approval-request") {
		t.Errorf("expected approval-request tag in operator campfire; msgs=%+v", msgs)
	}
}

// ---- F1G-c: message-operator --------------------------------------------------

func TestMessageOperator_InputValidation(t *testing.T) {
	err := dispatchActionTool("message-operator",
		`{"finding_id":"fnd-1","message":"","category":"informational"}`)
	if err == nil || !strings.Contains(err.Error(), "message") {
		t.Errorf("expected message error, got: %v", err)
	}
	// Invalid category.
	err = dispatchActionTool("message-operator",
		`{"finding_id":"fnd-1","message":"hello","category":"invalid-cat"}`)
	if err == nil || !strings.Contains(err.Error(), "category") {
		t.Errorf("expected category error, got: %v", err)
	}
}

func TestMessageOperator_PostsToOperatorCampfire(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, operatorCampfireID := newTestCampfire(t, cfBin)

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "message-operator",
			`{"finding_id":"fnd-msg-001","message":"Investigation complete. Unusual login from new IP traced to VPN endpoint. No breach.","category":"informational"}`,
			"MALLCOP_OPERATOR_CAMPFIRE_ID", operatorCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("message-operator: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output: %v\nout=%q", err, out)
	}
	if result["message_id"] == nil || result["message_id"] == "" {
		t.Errorf("message_id must be non-empty")
	}

	// Verify campfire: finding: and category: tags present.
	msgs := readCampfireMessages(t, cfBin, cfHome, operatorCampfireID)
	if !hasTagInMessages(msgs, "finding:fnd-msg-001") {
		t.Errorf("expected finding:fnd-msg-001 tag in campfire; msgs=%+v", msgs)
	}
	if !hasTagInMessages(msgs, "category:informational") {
		t.Errorf("expected category:informational tag in campfire")
	}
}

// ---- F1G-d: approve-action ----------------------------------------------------

func TestApproveAction_OperatorReasonRequired(t *testing.T) {
	// Missing operator_reason — must be rejected.
	err := dispatchActionTool("approve-action",
		`{"gate_id":"gate-001","verdict":"approved"}`)
	if err == nil {
		t.Fatal("expected error when operator_reason missing, got nil")
	}
	if !strings.Contains(err.Error(), "operator_reason") {
		t.Errorf("error must mention operator_reason, got: %v", err)
	}
}

func TestApproveAction_NoDefaultVerdict(t *testing.T) {
	// Missing verdict must be rejected.
	err := dispatchActionTool("approve-action",
		`{"gate_id":"gate-001","operator_reason":"Human approved this action."}`)
	if err == nil {
		t.Fatal("expected error when verdict missing (no default), got nil")
	}
	if !strings.Contains(err.Error(), "verdict") {
		t.Errorf("error must mention verdict, got: %v", err)
	}
}

func TestApproveAction_InvalidVerdict(t *testing.T) {
	err := dispatchActionTool("approve-action",
		`{"gate_id":"gate-001","verdict":"maybe","operator_reason":"Human said maybe."}`)
	if err == nil {
		t.Fatal("expected error for invalid verdict, got nil")
	}
	if !strings.Contains(err.Error(), "approved|denied") {
		t.Errorf("error must mention approved|denied, got: %v", err)
	}
}

func TestApproveAction_FulfillsGateEndToEnd(t *testing.T) {
	cfBin := requireCFF(t)
	cfHome, operatorCampfireID := newTestCampfire(t, cfBin)

	// Step 1: create a gate (future message) via request-approval.
	var gateID string
	captureStdout(t, func() {
		err := runToolWithEnv(t, "request-approval",
			`{"finding_id":"fnd-approve-e2e","action_name":"disable-account","justification":"Test justification: account shows clear signs of compromise."}`,
			"MALLCOP_OPERATOR_CAMPFIRE_ID", operatorCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("request-approval: unexpected error: %v", err)
		}
	})

	// Read the gate ID from the campfire.
	msgs := readCampfireMessages(t, cfBin, cfHome, operatorCampfireID)
	for _, msg := range msgs {
		if hasTagInMessages([]map[string]interface{}{msg}, "approval-request") {
			if id, ok := msg["id"].(string); ok && id != "" {
				gateID = id
				break
			}
		}
	}
	if gateID == "" {
		t.Fatal("could not find gate message ID in campfire")
	}

	// Step 2: fulfill the gate via approve-action.
	approveInputJSON, _ := json.Marshal(map[string]interface{}{
		"gate_id":         gateID,
		"verdict":         "approved",
		"operator_reason": "Human operator reviewed and approved: VPN endpoint confirmed as safe, no further action needed.",
	})

	out := captureStdout(t, func() {
		err := runToolWithEnv(t, "approve-action",
			string(approveInputJSON),
			"MALLCOP_OPERATOR_CAMPFIRE_ID", operatorCampfireID,
			"CF_HOME", cfHome,
		)
		if err != nil {
			t.Errorf("approve-action: unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse approve-action output: %v\nout=%q", err, out)
	}
	if result["verdict"] != "approved" {
		t.Errorf("verdict = %v, want approved", result["verdict"])
	}
	if result["fulfill_message_id"] == nil || result["fulfill_message_id"] == "" {
		t.Errorf("fulfill_message_id must be non-empty")
	}

	// Verify audit trail: approval:audit tag present in campfire.
	afterMsgs := readCampfireMessages(t, cfBin, cfHome, operatorCampfireID)
	if !hasTagInMessages(afterMsgs, "approval:audit") {
		t.Errorf("expected approval:audit tag in campfire after approve-action; msgs=%+v", afterMsgs)
	}
	if !hasTagInMessages(afterMsgs, "verdict:approved") {
		t.Errorf("expected verdict:approved tag in campfire after approve-action")
	}
}
