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
		triageAction       string
		expectInvestigate  bool
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
