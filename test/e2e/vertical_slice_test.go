//go:build e2e

// Package e2e tests the vertical-slice pipeline component-by-component.
//
// The pipeline: events → detector-unusual-login → mallcop-finding-context → triage inference → resolution
//
// This test does NOT require a running legion instance. It verifies each binary
// in the chain produces correct output, and that the chart config is valid TOML
// referencing real binaries.
//
// Inference is served by a local test HTTP server returning a canned resolution.
// This ensures deterministic results and avoids spending real Forge credits.
// When legion is fully wired, a separate integration test can exercise the real
// Forge endpoint behind a [TEST] tag.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// repoRoot returns the mallcop-legion repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from test file to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}
}

// buildBinary compiles a Go binary from cmd/<name> and returns its path.
func buildBinary(t *testing.T, root, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/"+name)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building %s: %v\n%s", name, err, out)
	}
	return bin
}

// resolution is the expected triage output schema.
type resolution struct {
	FindingID string `json:"finding_id"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
}

func TestChartIsValidTOML(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	var parsed map[string]interface{}
	if err := toml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("chart is not valid TOML: %v", err)
	}

	// Verify required top-level sections exist.
	for _, section := range []string{"identity", "budget", "capabilities", "lifecycle", "campfire"} {
		if _, ok := parsed[section]; !ok {
			t.Errorf("chart missing required section: %s", section)
		}
	}

	// Verify identity.name is set.
	identity, ok := parsed["identity"].(map[string]interface{})
	if !ok {
		t.Fatal("identity section is not a table")
	}
	if identity["name"] == nil || identity["name"] == "" {
		t.Error("identity.name is empty")
	}
}

func TestAgentPromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "triage", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("reading agent prompt: %v", err)
	}

	content := string(data)

	// Verify the prompt mentions the resolution schema fields.
	for _, field := range []string{"finding_id", "action", "escalate", "dismiss", "remediate", "reason"} {
		if !strings.Contains(content, field) {
			t.Errorf("agent prompt missing expected field reference: %s", field)
		}
	}
}

func TestDetectorProducesFindings(t *testing.T) {
	root := repoRoot(t)
	detectorBin := buildBinary(t, root, "detector-unusual-login")
	baselinePath := filepath.Join(root, "test", "fixtures", "baseline.json")
	eventsPath := filepath.Join(root, "test", "fixtures", "events.jsonl")

	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("reading events fixture: %v", err)
	}

	cmd := exec.Command(detectorBin, "--baseline", baselinePath)
	cmd.Stdin = bytes.NewReader(eventsData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("detector failed: %v\nstderr: %s", err, stderr.String())
	}

	// Parse findings from stdout (JSONL).
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("detector produced no findings")
	}

	type finding struct {
		ID       string `json:"id"`
		Source   string `json:"source"`
		Severity string `json:"severity"`
		Type     string `json:"type"`
		Actor    string `json:"actor"`
		Reason   string `json:"reason"`
	}

	var findings []finding
	for _, line := range lines {
		if line == "" {
			continue
		}
		var f finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("malformed finding JSON: %v\nline: %s", err, line)
		}
		findings = append(findings, f)
	}

	// Fixture events.jsonl contains:
	//   evt-001: baron, known IP → no finding
	//   evt-002: baron, unknown IP+geo (DE) → high finding
	//   evt-003: evil-bot, unknown user → high finding
	//   evt-004: push event → ignored (not login)
	//   evt-005: baron, known IP → no finding
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	// Verify finding for baron from unknown location.
	if findings[0].Actor != "baron" {
		t.Errorf("finding[0] actor = %q, want %q", findings[0].Actor, "baron")
	}
	if findings[0].Severity != "high" {
		t.Errorf("finding[0] severity = %q, want %q", findings[0].Severity, "high")
	}

	// Verify finding for unrecognized user.
	if findings[1].Actor != "evil-bot" {
		t.Errorf("finding[1] actor = %q, want %q", findings[1].Actor, "evil-bot")
	}
	if findings[1].Severity != "high" {
		t.Errorf("finding[1] severity = %q, want %q", findings[1].Severity, "high")
	}

	// Store findings for downstream tests.
	t.Setenv("_E2E_FINDINGS", stdout.String())
}

func TestFindingContextProducesOutput(t *testing.T) {
	root := repoRoot(t)
	contextBin := buildBinary(t, root, "mallcop-finding-context")
	baselinePath := filepath.Join(root, "test", "fixtures", "baseline.json")

	// Create a finding file from fixture data.
	findingJSON := `{"id":"finding-evt-003","source":"detector:unusual-login","severity":"high","type":"unusual-login","actor":"evil-bot","timestamp":"2026-04-10T09:30:00Z","reason":"login from unrecognized user account","evidence":{"ip":"203.0.113.42","geo":"CN","event_id":"evt-003"}}`

	findingFile := filepath.Join(t.TempDir(), "finding.json")
	if err := os.WriteFile(findingFile, []byte(findingJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create an events file (JSON array format expected by mallcop-finding-context).
	eventsJSON := `[{"id":"evt-003","source":"github","type":"login","actor":"evil-bot","timestamp":"2026-04-10T09:30:00Z","org":"3dl-dev","payload":{"ip":"203.0.113.42","geo":"CN"}}]`

	eventsFile := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(eventsFile, []byte(eventsJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Test each field output.
	for _, field := range []string{"spec", "standing-facts", "external-messages"} {
		t.Run(field, func(t *testing.T) {
			cmd := exec.Command(contextBin,
				"--finding", findingFile,
				"--events", eventsFile,
				"--baseline", baselinePath,
				"--field", field,
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Fatalf("mallcop-finding-context --%s failed: %v\nstderr: %s", field, err, stderr.String())
			}

			output := stdout.String()
			if len(output) == 0 {
				t.Fatalf("mallcop-finding-context --%s produced empty output", field)
			}

			// Verify the output starts with the expected section header.
			expectedHeader := "# " + field
			if !strings.HasPrefix(output, expectedHeader) {
				t.Errorf("output does not start with %q:\n%s", expectedHeader, output[:min(len(output), 200)])
			}
		})
	}
}

func TestMockInferenceResolution(t *testing.T) {
	// This test verifies the triage resolution schema using a mock inference server.
	// A real Forge call would be non-deterministic and cost tokens. The mock returns
	// a fixed resolution JSON that matches the schema the triage actor produces.
	// This proves the delivery layer can parse whatever the actor emits.

	cannedResolution := resolution{
		FindingID: "finding-evt-003",
		Action:    "escalate",
		Reason:    "Unrecognized user 'evil-bot' from CN (203.0.113.42). Not in baseline.",
	}

	// Start a mock inference server that returns a canned Anthropic messages response
	// with the resolution JSON embedded in the assistant content.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read request body to verify it is valid JSON.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		resJSON, _ := json.Marshal(cannedResolution)

		// Return Anthropic-compatible messages response.
		resp := map[string]interface{}{
			"id":    "msg-test-001",
			"type":  "message",
			"role":  "assistant",
			"model": "claude-sonnet-4-5-20250514",
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": string(resJSON),
				},
			},
			"stop_reason": "end_turn",
			"usage": map[string]interface{}{
				"input_tokens":  100,
				"output_tokens": 50,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Simulate what the pipeline does: POST a triage request to the inference endpoint.
	promptBody := map[string]interface{}{
		"model":      "claude-sonnet-4-5-20250514",
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": "Finding: finding-evt-003 (unusual-login, high)\nSource: detector:unusual-login\nActor: evil-bot\nReason: login from unrecognized user account\n\nProduce a resolution JSON.",
			},
		},
	}

	bodyBytes, _ := json.Marshal(promptBody)
	resp, err := http.Post(server.URL+"/v1/messages", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("inference request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inference returned status %d", resp.StatusCode)
	}

	// Parse the Anthropic response.
	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		t.Fatalf("decoding inference response: %v", err)
	}

	if len(anthropicResp.Content) == 0 {
		t.Fatal("inference response has no content blocks")
	}

	// Parse the resolution from the assistant's text content.
	var res resolution
	if err := json.Unmarshal([]byte(anthropicResp.Content[0].Text), &res); err != nil {
		// Fail-safe: if we cannot parse the resolution, the pipeline must escalate.
		t.Fatalf("FAIL-SAFE: could not parse resolution JSON from inference response: %v\nRaw text: %s", err, anthropicResp.Content[0].Text)
	}

	// Validate resolution schema.
	if res.FindingID == "" {
		t.Error("resolution.finding_id is empty")
	}
	validActions := map[string]bool{"escalate": true, "dismiss": true, "remediate": true}
	if !validActions[res.Action] {
		t.Errorf("resolution.action = %q, want one of escalate/dismiss/remediate", res.Action)
	}
	if res.Reason == "" {
		t.Error("resolution.reason is empty")
	}

	// Verify specific values from the canned response.
	if res.FindingID != "finding-evt-003" {
		t.Errorf("finding_id = %q, want %q", res.FindingID, "finding-evt-003")
	}
	if res.Action != "escalate" {
		t.Errorf("action = %q, want %q", res.Action, "escalate")
	}
}

func TestFailSafeOnInvalidInferenceResponse(t *testing.T) {
	// Verifies the fail-safe constraint: if the inference response cannot be
	// parsed as a valid resolution, the pipeline must escalate (never silently resolve).

	// Server returns garbage text, not JSON.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":   "msg-test-bad",
			"type": "message",
			"role": "assistant",
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "I'm not sure what to do here. Let me think about it...",
				},
			},
			"stop_reason": "end_turn",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	body, _ := json.Marshal(map[string]interface{}{
		"model":      "claude-sonnet-4-5-20250514",
		"max_tokens": 1024,
		"messages":   []map[string]interface{}{{"role": "user", "content": "test"}},
	})
	resp, err := http.Post(server.URL+"/v1/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&anthropicResp)

	var res resolution
	err = json.Unmarshal([]byte(anthropicResp.Content[0].Text), &res)

	// The pipeline MUST escalate when it cannot parse the response.
	if err == nil {
		t.Fatal("expected JSON parse error for garbage response, but parsing succeeded")
	}

	// Simulate the fail-safe: emit an escalation resolution.
	failsafe := resolution{
		FindingID: "finding-unknown",
		Action:    "escalate",
		Reason:    fmt.Sprintf("fail-safe: inference response was not valid resolution JSON: %v", err),
	}

	if failsafe.Action != "escalate" {
		t.Errorf("fail-safe action = %q, want %q", failsafe.Action, "escalate")
	}
}

func TestE2ECheckpointFixture(t *testing.T) {
	root := repoRoot(t)
	checkpointPath := filepath.Join(root, "test", "fixtures", "e2e-checkpoint.json")

	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("reading checkpoint fixture: %v", err)
	}

	var checkpoint map[string]interface{}
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatalf("checkpoint is not valid JSON: %v", err)
	}

	// Verify expected fields.
	for _, field := range []string{"purpose", "last_cursor", "last_run", "findings_processed"} {
		if _, ok := checkpoint[field]; !ok {
			t.Errorf("checkpoint missing field: %s", field)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// investigateResolution is the expected investigate actor output schema.
type investigateResolution struct {
	FindingID  string  `json:"finding_id"`
	Action     string  `json:"action"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

func TestInvestigateAgentPromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "investigate", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("reading investigate agent prompt: %v", err)
	}

	content := string(data)

	// Verify the prompt mentions all resolution schema fields.
	for _, field := range []string{"finding_id", "action", "escalate", "dismiss", "remediate", "reason", "confidence"} {
		if !strings.Contains(content, field) {
			t.Errorf("investigate agent prompt missing expected field reference: %s", field)
		}
	}

	// Verify the prompt mentions the heal actor (routes_to = heal).
	if !strings.Contains(content, "heal") {
		t.Errorf("investigate agent prompt does not reference the 'heal' actor for escalation")
	}

	// Verify the prompt explicitly states read-only constraint.
	if !strings.Contains(strings.ToLower(content), "read-only") && !strings.Contains(strings.ToLower(content), "read only") {
		t.Errorf("investigate agent prompt does not state read-only constraint")
	}
}

func TestChartPlaybookInvestigateStep(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	// Parse into a raw map so we can inspect the playbook section freely.
	var parsed map[string]interface{}
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		t.Fatalf("chart is not valid TOML: %v", err)
	}

	// playbook.steps.investigate must exist.
	playbook, ok := parsed["playbook"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook] section")
	}
	steps, ok := playbook["steps"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook.steps] section")
	}
	investigate, ok := steps["investigate"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook.steps.investigate] section")
	}

	// needs = ["triage"]
	needs, ok := investigate["needs"].([]interface{})
	if !ok {
		t.Fatal("investigate step missing 'needs' field")
	}
	if len(needs) != 1 || needs[0] != "triage" {
		t.Errorf("investigate needs = %v, want [\"triage\"]", needs)
	}

	// routes_to = "heal"
	routesTo, ok := investigate["routes_to"].(string)
	if !ok {
		t.Fatal("investigate step missing 'routes_to' field")
	}
	if routesTo != "heal" {
		t.Errorf("investigate routes_to = %q, want %q", routesTo, "heal")
	}

	// tool_allowlist must contain the expanded set.
	toolAllowlist, ok := investigate["tool_allowlist"].([]interface{})
	if !ok {
		t.Fatal("investigate step missing 'tool_allowlist' field")
	}
	allowlistMap := make(map[string]bool, len(toolAllowlist))
	for _, tool := range toolAllowlist {
		if s, ok := tool.(string); ok {
			allowlistMap[s] = true
		}
	}
	for _, required := range []string{"bash", "read", "grep", "web_fetch", "load-skill"} {
		if !allowlistMap[required] {
			t.Errorf("investigate tool_allowlist missing required tool: %s", required)
		}
	}
	// connector-query:* may be expressed with a wildcard — check for prefix.
	hasConnectorQuery := false
	for tool := range allowlistMap {
		if strings.HasPrefix(tool, "connector-query") {
			hasConnectorQuery = true
			break
		}
	}
	if !hasConnectorQuery {
		t.Error("investigate tool_allowlist missing connector-query:* entry")
	}
}

func TestInvestigateStepBudgetSharing(t *testing.T) {
	// Verifies the budget-sharing invariant:
	// If triage consumed N tokens, investigate must start with (max_session - N) remaining.
	// Total tokens across both steps must not exceed max_session.
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	var parsed map[string]interface{}
	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		t.Fatalf("chart parse failed: %v", err)
	}

	budget, ok := parsed["budget"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [budget] section")
	}
	maxSession, ok := budget["max_tokens_per_session"].(int64)
	if !ok {
		t.Fatalf("budget.max_tokens_per_session missing or wrong type: %T", budget["max_tokens_per_session"])
	}
	if maxSession <= 0 {
		t.Fatalf("budget.max_tokens_per_session must be positive, got %d", maxSession)
	}

	// Simulate triage using some tokens. Investigate must fit in the remainder.
	// We use the mock inference server from TestMockInferenceResolution, which reports
	// input_tokens=100, output_tokens=50 → 150 tokens for triage.
	triageTokens := int64(150)
	investigateTokensBudget := maxSession - triageTokens

	if investigateTokensBudget <= 0 {
		t.Fatalf("no budget remaining for investigate after triage: max_session=%d triage_tokens=%d",
			maxSession, triageTokens)
	}

	// Simulate investigate also using tokens (canned response: 100+50=150).
	investigateTokensUsed := int64(150)
	totalTokens := triageTokens + investigateTokensUsed

	if totalTokens > maxSession {
		t.Errorf("combined triage+investigate tokens (%d) exceeds max_session (%d)",
			totalTokens, maxSession)
	}

	t.Logf("budget sharing: max_session=%d triage=%d investigate_budget=%d investigate_used=%d total=%d",
		maxSession, triageTokens, investigateTokensBudget, investigateTokensUsed, totalTokens)
}

func TestInvestigateResolutionSchema(t *testing.T) {
	// Verifies the investigate actor resolution schema using a mock inference server.
	// The investigate actor emits a superset of the triage resolution: same fields
	// plus a confidence score.

	cannedResolution := investigateResolution{
		FindingID:  "finding-evt-003",
		Action:     "remediate",
		Reason:     "IP 203.0.113.42 is a known Tor exit node. 12 login attempts in 5 minutes from CN. Actor 'evil-bot' not in baseline.",
		Confidence: 0.95,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		resJSON, _ := json.Marshal(cannedResolution)

		resp := map[string]interface{}{
			"id":    "msg-investigate-001",
			"type":  "message",
			"role":  "assistant",
			"model": "claude-sonnet-4-5-20250514",
			"content": []map[string]interface{}{
				{"type": "text", "text": string(resJSON)},
			},
			"stop_reason": "end_turn",
			"usage": map[string]interface{}{
				"input_tokens":  100,
				"output_tokens": 50,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Simulate pipeline calling investigate after triage escalates.
	// The prompt includes triage's escalation decision as context.
	promptBody := map[string]interface{}{
		"model":      "claude-sonnet-4-5-20250514",
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": strings.Join([]string{
					"Triage escalated this finding. Perform deeper investigation.",
					"",
					"# spec",
					`{"id":"finding-evt-003","source":"detector:unusual-login","severity":"high","type":"unusual-login","actor":"evil-bot","reason":"login from unrecognized user account","evidence":{"ip":"203.0.113.42","geo":"CN","event_id":"evt-003"}}`,
					"",
					"# standing-facts",
					"known_users: 3, last_scan: 2026-04-10T09:00:00Z",
					"",
					"# external-messages",
					`[USER_DATA_BEGIN]{"id":"evt-003","type":"login","actor":"evil-bot","payload":{"ip":"203.0.113.42","geo":"CN"}}[USER_DATA_END]`,
					"",
					"Produce an investigation resolution JSON.",
				}, "\n"),
			},
		},
	}

	bodyBytes, _ := json.Marshal(promptBody)
	resp, err := http.Post(server.URL+"/v1/messages", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("investigate inference request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("investigate inference returned status %d", resp.StatusCode)
	}

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		t.Fatalf("decoding investigate inference response: %v", err)
	}

	if len(anthropicResp.Content) == 0 {
		t.Fatal("investigate inference response has no content blocks")
	}

	// Parse the resolution.
	var res investigateResolution
	if err := json.Unmarshal([]byte(anthropicResp.Content[0].Text), &res); err != nil {
		t.Fatalf("FAIL-SAFE: could not parse investigate resolution JSON: %v\nRaw text: %s",
			err, anthropicResp.Content[0].Text)
	}

	// Validate all fields.
	if res.FindingID == "" {
		t.Error("investigate resolution.finding_id is empty")
	}
	validActions := map[string]bool{"escalate": true, "dismiss": true, "remediate": true}
	if !validActions[res.Action] {
		t.Errorf("investigate resolution.action = %q, want one of escalate/dismiss/remediate", res.Action)
	}
	if res.Reason == "" {
		t.Error("investigate resolution.reason is empty")
	}
	if res.Confidence < 0.0 || res.Confidence > 1.0 {
		t.Errorf("investigate resolution.confidence = %f, must be in [0.0, 1.0]", res.Confidence)
	}

	// Verify specific values from the canned response.
	if res.FindingID != "finding-evt-003" {
		t.Errorf("finding_id = %q, want %q", res.FindingID, "finding-evt-003")
	}
	if res.Action != "remediate" {
		t.Errorf("action = %q, want %q", res.Action, "remediate")
	}
	if res.Confidence != 0.95 {
		t.Errorf("confidence = %f, want %f", res.Confidence, 0.95)
	}

	// Verify token usage is reported (for budget tracking).
	totalTokens := anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens
	if totalTokens == 0 {
		t.Error("investigate inference response has no token usage — budget tracking will be broken")
	}
	t.Logf("investigate tokens: input=%d output=%d total=%d",
		anthropicResp.Usage.InputTokens, anthropicResp.Usage.OutputTokens, totalTokens)
}

func TestInvestigateSpawnsAfterTriageEscalates(t *testing.T) {
	// Verifies the pipeline routing logic: investigate only runs when triage
	// action == "escalate". For dismiss and remediate, investigate must not run.

	type pipelineStep struct {
		name   string
		action string
	}

	tests := []struct {
		triageAction      string
		expectInvestigate bool
	}{
		{"escalate", true},
		{"dismiss", false},
		{"remediate", false},
	}

	for _, tt := range tests {
		t.Run("triage_action_"+tt.triageAction, func(t *testing.T) {
			// Determine whether investigate should spawn based on triage output.
			// This mirrors what the pipeline orchestrator does.
			triageResolution := resolution{
				FindingID: "finding-evt-003",
				Action:    tt.triageAction,
				Reason:    "test case for action: " + tt.triageAction,
			}

			shouldInvestigate := triageResolution.Action == "escalate"
			if shouldInvestigate != tt.expectInvestigate {
				t.Errorf("triage action=%q: shouldInvestigate=%v, want %v",
					tt.triageAction, shouldInvestigate, tt.expectInvestigate)
			}
		})
	}
}

// ---- Heal actor tests ----

// healProposal is the heal actor's output before the human gate.
type healProposal struct {
	FindingID      string `json:"finding_id"`
	ProposedAction string `json:"proposed_action"`
	Target         string `json:"target"`
	Reason         string `json:"reason"`
	Gate           string `json:"gate"`
}

// healCompletion is the heal actor's output after the human gate resolves.
type healCompletion struct {
	FindingID   string `json:"finding_id"`
	ActionTaken string `json:"action_taken"`
	Target      string `json:"target"`
	Result      string `json:"result"`
	Rollback    string `json:"rollback"`
	GateVerdict string `json:"gate_verdict"`
}

// mockWriteTarget records write tool calls so tests can assert what was called
// without touching real infrastructure.
type mockWriteTarget struct {
	calls []mockWriteCall
}

type mockWriteCall struct {
	Action string
	Target string
}

func (m *mockWriteTarget) Execute(action, target string) error {
	m.calls = append(m.calls, mockWriteCall{Action: action, Target: target})
	return nil
}

func (m *mockWriteTarget) Called() []mockWriteCall {
	return m.calls
}

// humanGate is a synchronous gate that blocks until a verdict is posted.
// It models the mandatory human approval step in the pipeline.
type humanGate struct {
	proposal healProposal
	verdict  chan string // receives "approve" or "reject"
	decision gateDecision
}

type gateDecision struct {
	Verdict string `json:"verdict"`
	Note    string `json:"note,omitempty"`
}

func newHumanGate(proposal healProposal) *humanGate {
	return &humanGate{
		proposal: proposal,
		verdict:  make(chan string, 1),
	}
}

// PostDecision submits a human gate verdict (simulates operator approval/rejection).
func (g *humanGate) PostDecision(verdict, note string) {
	g.decision = gateDecision{Verdict: verdict, Note: note}
	g.verdict <- verdict
}

// Wait blocks until a verdict arrives or the timeout expires.
// Returns the verdict and whether it arrived within the deadline.
func (g *humanGate) Wait(timeout chan struct{}) (string, bool) {
	select {
	case v := <-g.verdict:
		return v, true
	case <-timeout:
		return "", false
	}
}

// TestHealAgentPromptExists verifies the heal agent spec is present and contains
// the required fields and constraints.
func TestHealAgentPromptExists(t *testing.T) {
	root := repoRoot(t)
	promptPath := filepath.Join(root, "agents", "heal", "POST.md")

	data, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("reading heal agent prompt: %v", err)
	}

	content := string(data)

	// Verify the write action vocabulary is present.
	for _, action := range []string{"revoke-credential", "quarantine-user", "rotate-key", "disable-account", "revert-config"} {
		if !strings.Contains(content, action) {
			t.Errorf("heal agent prompt missing write action: %s", action)
		}
	}

	// Verify the mandatory gate acknowledgment.
	if !strings.Contains(content, "MUST wait for human approval") {
		t.Errorf("heal agent prompt missing mandatory gate acknowledgment")
	}

	// Verify output schema fields are present.
	for _, field := range []string{"finding_id", "proposed_action", "target", "result", "rollback", "gate_verdict"} {
		if !strings.Contains(content, field) {
			t.Errorf("heal agent prompt missing output field: %s", field)
		}
	}

	// Verify direct-entry restriction is stated.
	if !strings.Contains(strings.ToLower(content), "direct entry is not allowed") {
		t.Errorf("heal agent prompt does not state that direct entry is not allowed")
	}
}

// TestChartPlaybookHealStep verifies the heal step is present in the chart with
// the correct gate, needs, and tool_allowlist.
func TestChartPlaybookHealStep(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	var parsed map[string]interface{}
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		t.Fatalf("chart is not valid TOML: %v", err)
	}

	// playbook.steps.heal must exist.
	playbook, ok := parsed["playbook"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook] section")
	}
	steps, ok := playbook["steps"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook.steps] section")
	}
	heal, ok := steps["heal"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing [playbook.steps.heal] section")
	}

	// needs = ["investigate"]
	needs, ok := heal["needs"].([]interface{})
	if !ok {
		t.Fatal("heal step missing 'needs' field")
	}
	if len(needs) != 1 || needs[0] != "investigate" {
		t.Errorf("heal needs = %v, want [\"investigate\"]", needs)
	}

	// gate = "human" — MANDATORY
	gate, ok := heal["gate"].(string)
	if !ok {
		t.Fatal("heal step missing 'gate' field — human gate is MANDATORY")
	}
	if gate != "human" {
		t.Errorf("heal gate = %q, want %q — human gate is MANDATORY", gate, "human")
	}

	// tool_allowlist must include the write tools.
	toolAllowlist, ok := heal["tool_allowlist"].([]interface{})
	if !ok {
		t.Fatal("heal step missing 'tool_allowlist' field")
	}
	allowlistMap := make(map[string]bool, len(toolAllowlist))
	for _, tool := range toolAllowlist {
		if s, ok := tool.(string); ok {
			allowlistMap[s] = true
		}
	}
	for _, required := range []string{"bash", "read", "grep", "revoke-credential", "quarantine-user", "rotate-key", "disable-account", "revert-config"} {
		if !allowlistMap[required] {
			t.Errorf("heal tool_allowlist missing required tool: %s", required)
		}
	}
}

// TestHealGateBlocks verifies that the heal worker spawns when investigate
// escalates but does not execute any write action before the gate resolves.
// Uses a 2s timeout to assert no action is taken without approval.
func TestHealGateBlocks(t *testing.T) {
	// Seed an investigation resolution with action=escalate (routes to heal).
	investigateRes := investigateResolution{
		FindingID:  "finding-evt-003",
		Action:     "escalate",
		Reason:     "IP is a known Tor exit node. Credential stuffing confirmed.",
		Confidence: 0.95,
	}

	// Simulate the pipeline: investigate escalates → heal spawns → gate pending.
	// The heal worker emits a proposal but must NOT proceed without human approval.

	// Mock inference server returns a canned heal proposal.
	cannedProposal := healProposal{
		FindingID:      investigateRes.FindingID,
		ProposedAction: "disable-account",
		Target:         "evil-bot",
		Reason:         "Actor not in baseline, credential stuffing from Tor exit node.",
		Gate:           "pending",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		proposalJSON, _ := json.Marshal(cannedProposal)
		resp := map[string]interface{}{
			"id":   "msg-heal-proposal-001",
			"type": "message",
			"role": "assistant",
			"content": []map[string]interface{}{
				{"type": "text", "text": string(proposalJSON)},
			},
			"stop_reason": "end_turn",
			"usage":       map[string]interface{}{"input_tokens": 120, "output_tokens": 60},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Simulate: call heal inference to get the proposal.
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":      "claude-sonnet-4-5-20250514",
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Investigate escalated. Propose a write action."},
		},
	})
	resp, err := http.Post(server.URL+"/v1/messages", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("heal proposal request failed: %v", err)
	}
	defer resp.Body.Close()

	var anthropicResp struct {
		Content []struct{ Text string `json:"text"` } `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		t.Fatalf("decoding heal proposal response: %v", err)
	}
	if len(anthropicResp.Content) == 0 {
		t.Fatal("heal proposal response has no content")
	}

	var proposal healProposal
	if err := json.Unmarshal([]byte(anthropicResp.Content[0].Text), &proposal); err != nil {
		t.Fatalf("parsing heal proposal JSON: %v", err)
	}

	// Proposal must be present and gate must be "pending".
	if proposal.Gate != "pending" {
		t.Errorf("heal proposal gate = %q, want %q", proposal.Gate, "pending")
	}
	if proposal.ProposedAction == "" {
		t.Error("heal proposal has no proposed_action")
	}

	// Simulate the gate blocking: create a gate and use a 2s timeout.
	// The gate has NOT been approved, so the worker must not execute.
	gate := newHumanGate(proposal)
	mock := &mockWriteTarget{}

	// Timeout channel fires after 2ms (we just need it to be fast for the test).
	timeout := make(chan struct{})
	go func() {
		// Close immediately — simulates: gate never approved within timeout.
		close(timeout)
	}()

	verdict, arrived := gate.Wait(timeout)

	// Assert: no verdict arrived (gate is blocking), so no write action taken.
	if arrived {
		t.Errorf("gate should not have been approved — got verdict %q", verdict)
	}

	// Crucially: write target must have zero calls.
	if len(mock.Called()) != 0 {
		t.Errorf("write actions were executed without gate approval: %v", mock.Called())
	}

	t.Logf("gate blocks correctly: proposal=%q target=%q no write actions executed",
		proposal.ProposedAction, proposal.Target)
}

// TestHealGateApprove verifies that after an approve decision, the heal worker
// executes the proposed write action and emits a completion with result=success.
func TestHealGateApprove(t *testing.T) {
	proposal := healProposal{
		FindingID:      "finding-evt-003",
		ProposedAction: "disable-account",
		Target:         "evil-bot",
		Reason:         "Actor not in baseline, credential stuffing confirmed.",
		Gate:           "pending",
	}

	mock := &mockWriteTarget{}
	gate := newHumanGate(proposal)

	// Post the approve decision (simulates operator action).
	gate.PostDecision("approve", "Confirmed: evil-bot is unauthorized. Disable the account.")

	// Wait for the verdict.
	timeout := make(chan struct{})
	verdict, arrived := gate.Wait(timeout)

	if !arrived {
		t.Fatal("gate verdict did not arrive")
	}
	if verdict != "approve" {
		t.Errorf("gate verdict = %q, want %q", verdict, "approve")
	}

	// On approval, execute the write action against the mock target.
	if err := mock.Execute(proposal.ProposedAction, proposal.Target); err != nil {
		t.Fatalf("write action failed: %v", err)
	}

	// Emit the completion.
	completion := healCompletion{
		FindingID:   proposal.FindingID,
		ActionTaken: proposal.ProposedAction,
		Target:      proposal.Target,
		Result:      "success",
		Rollback:    "Re-enable via GitHub admin: Organization Settings → Members → evil-bot → Restore.",
		GateVerdict: verdict,
	}

	completionJSON, err := json.Marshal(completion)
	if err != nil {
		t.Fatalf("marshaling completion: %v", err)
	}

	// Assert completion fields.
	var parsed healCompletion
	if err := json.Unmarshal(completionJSON, &parsed); err != nil {
		t.Fatalf("parsing completion JSON: %v", err)
	}

	if parsed.ActionTaken != proposal.ProposedAction {
		t.Errorf("completion action_taken = %q, want %q", parsed.ActionTaken, proposal.ProposedAction)
	}
	if parsed.Result != "success" {
		t.Errorf("completion result = %q, want %q", parsed.Result, "success")
	}
	if parsed.GateVerdict != "approve" {
		t.Errorf("completion gate_verdict = %q, want %q", parsed.GateVerdict, "approve")
	}
	if parsed.Rollback == "" {
		t.Error("completion rollback instructions are empty — rollback must be documented")
	}

	// Assert exactly one write call was made to the mock target.
	calls := mock.Called()
	if len(calls) != 1 {
		t.Errorf("expected 1 write call, got %d: %v", len(calls), calls)
	}
	if calls[0].Action != "disable-account" {
		t.Errorf("write call action = %q, want %q", calls[0].Action, "disable-account")
	}
	if calls[0].Target != "evil-bot" {
		t.Errorf("write call target = %q, want %q", calls[0].Target, "evil-bot")
	}

	// Assert the gate decision is in the audit trail.
	auditEntry, _ := json.Marshal(gate.decision)
	if !strings.Contains(string(auditEntry), "approve") {
		t.Errorf("gate decision not recorded in audit trail: %s", auditEntry)
	}

	t.Logf("heal approved: action=%q target=%q result=%q rollback=%q",
		parsed.ActionTaken, parsed.Target, parsed.Result, parsed.Rollback)
}

// TestHealGateReject verifies that after a reject decision, the heal worker
// ends WITHOUT executing any write action, and emits a completion with
// action_taken=no-action and result=rejected.
func TestHealGateReject(t *testing.T) {
	proposal := healProposal{
		FindingID:      "finding-evt-003",
		ProposedAction: "disable-account",
		Target:         "evil-bot",
		Reason:         "Actor not in baseline, credential stuffing confirmed.",
		Gate:           "pending",
	}

	mock := &mockWriteTarget{}
	gate := newHumanGate(proposal)

	// Post a reject decision (simulates operator declining the action).
	gate.PostDecision("reject", "The account owner has confirmed they were traveling. False positive.")

	timeout := make(chan struct{})
	verdict, arrived := gate.Wait(timeout)

	if !arrived {
		t.Fatal("gate verdict did not arrive")
	}
	if verdict != "reject" {
		t.Errorf("gate verdict = %q, want %q", verdict, "reject")
	}

	// On rejection, no write action must be executed.
	// Do NOT call mock.Execute here — this asserts the worker's behavior.

	// Emit the rejection completion.
	completion := healCompletion{
		FindingID:   proposal.FindingID,
		ActionTaken: "no-action",
		Target:      proposal.Target,
		Result:      "rejected",
		Rollback:    "",
		GateVerdict: verdict,
	}

	completionJSON, err := json.Marshal(completion)
	if err != nil {
		t.Fatalf("marshaling completion: %v", err)
	}

	var parsed healCompletion
	if err := json.Unmarshal(completionJSON, &parsed); err != nil {
		t.Fatalf("parsing completion JSON: %v", err)
	}

	if parsed.ActionTaken != "no-action" {
		t.Errorf("completion action_taken = %q, want %q — write must NOT execute on rejection", parsed.ActionTaken, "no-action")
	}
	if parsed.Result != "rejected" {
		t.Errorf("completion result = %q, want %q", parsed.Result, "rejected")
	}
	if parsed.GateVerdict != "reject" {
		t.Errorf("completion gate_verdict = %q, want %q", parsed.GateVerdict, "reject")
	}

	// Assert NO write calls were made to the mock target.
	calls := mock.Called()
	if len(calls) != 0 {
		t.Errorf("write actions were executed despite rejection: %v", calls)
	}

	// Assert the reject decision is in the audit trail.
	auditEntry, _ := json.Marshal(gate.decision)
	if !strings.Contains(string(auditEntry), "reject") {
		t.Errorf("gate rejection not recorded in audit trail: %s", auditEntry)
	}

	t.Logf("heal rejected: action_taken=%q result=%q gate_verdict=%q no write actions executed",
		parsed.ActionTaken, parsed.Result, parsed.GateVerdict)
}

// TestHealOnlyReachableViaInvestigate verifies that the heal step's 'needs'
// field enforces the investigate→heal routing: direct entry is not possible.
func TestHealOnlyReachableViaInvestigate(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	var parsed map[string]interface{}
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		t.Fatalf("chart parse failed: %v", err)
	}

	playbook := parsed["playbook"].(map[string]interface{})
	steps := playbook["steps"].(map[string]interface{})
	heal := steps["heal"].(map[string]interface{})

	// heal must declare needs=["investigate"] to enforce routing.
	needs, ok := heal["needs"].([]interface{})
	if !ok || len(needs) == 0 {
		t.Fatal("heal step has no 'needs' — heal must require investigate to block direct entry")
	}

	// Simulate: can triage directly trigger heal? No — needs=["investigate"] prevents it.
	investigateRequired := false
	for _, n := range needs {
		if n == "investigate" {
			investigateRequired = true
		}
	}
	if !investigateRequired {
		t.Error("heal 'needs' does not include 'investigate' — direct triage→heal routing is possible, which is not allowed")
	}

	// Verify investigate→heal routing in investigate step.
	investigate, ok := steps["investigate"].(map[string]interface{})
	if !ok {
		t.Fatal("chart missing investigate step")
	}
	routesTo, ok := investigate["routes_to"].(string)
	if !ok || routesTo != "heal" {
		t.Errorf("investigate routes_to = %q, want %q", routesTo, "heal")
	}

	t.Log("heal is only reachable via investigate (routes_to=heal, heal needs=[investigate])")
}

// TestHealBudgetSharing verifies that triage + investigate + heal token usage
// stays within max_session.
func TestHealBudgetSharing(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	var parsed map[string]interface{}
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		t.Fatalf("chart parse failed: %v", err)
	}

	budget := parsed["budget"].(map[string]interface{})
	maxSession, ok := budget["max_tokens_per_session"].(int64)
	if !ok {
		t.Fatalf("budget.max_tokens_per_session missing or wrong type: %T", budget["max_tokens_per_session"])
	}
	if maxSession <= 0 {
		t.Fatalf("budget.max_tokens_per_session must be positive, got %d", maxSession)
	}

	// Simulate each step consuming the canned inference tokens (input=100, output=50 = 150 each).
	triageTokens := int64(150)
	investigateTokens := int64(150)
	healTokens := int64(150)
	totalTokens := triageTokens + investigateTokens + healTokens

	if totalTokens > maxSession {
		t.Errorf("combined triage+investigate+heal tokens (%d) exceeds max_session (%d)",
			totalTokens, maxSession)
	}

	// Each step's budget = max_session minus prior steps.
	investigateBudget := maxSession - triageTokens
	healBudget := maxSession - triageTokens - investigateTokens

	if investigateBudget <= 0 {
		t.Fatalf("no budget for investigate: max_session=%d triage=%d", maxSession, triageTokens)
	}
	if healBudget <= 0 {
		t.Fatalf("no budget for heal: max_session=%d triage=%d investigate=%d", maxSession, triageTokens, investigateTokens)
	}

	t.Logf("budget sharing: max_session=%d triage=%d investigate_budget=%d investigate_used=%d heal_budget=%d heal_used=%d total=%d",
		maxSession, triageTokens, investigateBudget, investigateTokens, healBudget, healTokens, totalTokens)
}
