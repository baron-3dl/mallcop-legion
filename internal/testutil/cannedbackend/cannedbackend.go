// Package cannedbackend provides a minimal HTTP server that mimics Forge's
// /v1/chat/completions and /v1/messages endpoints for integration and e2e tests.
//
// It lives under internal/testutil/ (not a _test.go file) so that both
// test/budget and test/quality can import it without cross-package build-tag
// complications.  The package is in internal/ so it is only accessible to
// modules rooted at github.com/thirdiv/mallcop-legion.
//
// For budget tests the canned responses cycle through triage/investigate/heal
// resolutions.  For the exam smoke test (ID-01-new-actor-benign-onboarding)
// the resolutions should cause the judge to emit a passing verdict.  A caller
// may override CannedResolutionFunc to supply scenario-specific content.
package cannedbackend

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// CannedBackend is a minimal HTTP server that mimics Forge's inference
// endpoints.  Each request is recorded and a fixed token count is returned so
// tests can have deterministic arithmetic.
type CannedBackend struct {
	// TokensPerResponse is the total token count (input+output) reported in
	// each response's usage field.  4000 by default; change before Start().
	TokensPerResponse int

	// CannedResolutionFunc, if non-nil, is called with the 0-indexed call
	// number and should return the assistant content string for that call.
	// Defaults to DefaultCannedResolutionForCall when nil.
	CannedResolutionFunc func(callIndex int) string

	server   *http.Server
	listener net.Listener

	mu       sync.Mutex
	requests []CannedRequest

	callCount atomic.Int64
}

// CannedRequest records one HTTP call received by the backend.
type CannedRequest struct {
	// Path is the HTTP request path (e.g., "/v1/chat/completions").
	Path string
	// Body is the raw request body.
	Body []byte
}

// Start binds to a random localhost port and begins serving.
// Call URL() to obtain the base URL after Start returns.
func (b *CannedBackend) Start() error {
	if b.TokensPerResponse == 0 {
		b.TokensPerResponse = 4000
	}
	if b.CannedResolutionFunc == nil {
		b.CannedResolutionFunc = DefaultCannedResolutionForCall
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("canned backend: listen: %w", err)
	}
	b.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", b.handleChatCompletions)
	// Also handle Anthropic-style endpoint in case the chart uses /v1/messages.
	mux.HandleFunc("/v1/messages", b.handleMessages)
	// Health probe.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	b.server = &http.Server{Handler: mux}
	go func() {
		if err := b.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("canned backend: serve error: %v", err)
		}
	}()
	return nil
}

// URL returns the base URL of the backend (e.g., "http://127.0.0.1:12345").
// Only valid after Start().
func (b *CannedBackend) URL() string {
	return "http://" + b.listener.Addr().String()
}

// Stop shuts down the backend.
func (b *CannedBackend) Stop() {
	if b.server != nil {
		_ = b.server.Close()
	}
}

// Requests returns a snapshot of all requests received so far.
func (b *CannedBackend) Requests() []CannedRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]CannedRequest, len(b.requests))
	copy(out, b.requests)
	return out
}

// CallCount returns the number of inference requests received.
func (b *CannedBackend) CallCount() int {
	return int(b.callCount.Load())
}

// TotalTokensReported returns the total token usage reported across all calls
// (CallCount * TokensPerResponse).
func (b *CannedBackend) TotalTokensReported() int {
	return b.CallCount() * b.TokensPerResponse
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleChatCompletions handles the OpenAI-compatible /v1/chat/completions
// endpoint used by Forge.
func (b *CannedBackend) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	b.record(r.URL.Path, body)

	// Split tokens roughly 80/20 input/output.
	inputTokens := int(float64(b.TokensPerResponse) * 0.8)
	outputTokens := b.TokensPerResponse - inputTokens

	step := b.CallCount() // 1-indexed after record() incremented callCount
	callIndex := step - 1
	cannedContent := b.CannedResolutionFunc(callIndex)

	resp := map[string]interface{}{
		"id":     fmt.Sprintf("chatcmpl-canned-%04d", step),
		"object": "chat.completion",
		"model":  "claude-sonnet-4-5-20250514",
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": cannedContent,
				},
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     inputTokens,
			"completion_tokens": outputTokens,
			"total_tokens":      b.TokensPerResponse,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("canned backend: encode response: %v", err)
	}
}

// handleMessages handles the Anthropic-compatible /v1/messages endpoint.
func (b *CannedBackend) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	b.record(r.URL.Path, body)

	inputTokens := int(float64(b.TokensPerResponse) * 0.8)
	outputTokens := b.TokensPerResponse - inputTokens

	step := b.CallCount()
	callIndex := step - 1
	cannedContent := b.CannedResolutionFunc(callIndex)

	resp := map[string]interface{}{
		"id":   fmt.Sprintf("msg-canned-%04d", step),
		"type": "message",
		"role": "assistant",
		"model": "claude-sonnet-4-5-20250514",
		"content": []map[string]interface{}{
			{"type": "text", "text": cannedContent},
		},
		"stop_reason": "end_turn",
		"usage": map[string]interface{}{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("canned backend: encode response: %v", err)
	}
}

func (b *CannedBackend) record(path string, body []byte) {
	b.callCount.Add(1)
	b.mu.Lock()
	b.requests = append(b.requests, CannedRequest{Path: path, Body: body})
	b.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Default canned content
// ---------------------------------------------------------------------------

// DefaultCannedResolutionForCall returns deterministic JSON resolution payloads
// for budget-test use:
//   - call 0 (triage):      action=escalate → triggers investigate
//   - call 1 (investigate): action=escalate → triggers heal
//   - call 2 (heal):        proposed_action=disable-account
func DefaultCannedResolutionForCall(callIndex int) string {
	switch callIndex {
	case 0: // triage
		return `{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned triage: unrecognized actor from unknown geo. Escalating for investigation."}`
	case 1: // investigate
		return `{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned investigate: confirmed credential stuffing from Tor exit node. Escalating to heal.","confidence":0.95}`
	case 2: // heal
		return `{"finding_id":"budget-test-finding-001","proposed_action":"disable-account","target":"test-attacker","reason":"Canned heal: disable account to stop ongoing attack.","gate":"pending"}`
	default:
		return fmt.Sprintf(`{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned response for call %d"}`, callIndex)
	}
}

// ExamID01CannedResolutionForCall returns canned content for the
// ID-01-new-actor-benign-onboarding exam scenario.  The responses are crafted
// to make the judge award reasoning_quality >= 3 and
// investigation_thoroughness >= 3, producing a "pass" verdict.
//
// Disposition flow:
//   - call 0 (triage/exam:scenario): resolve with benign assessment citing admin-user + business hours
//   - call 1 (judge/exam:judge):     emit judge:verdict JSON with pass verdict
//   - call 2+ (report/exam:report):  minimal acknowledgement
func ExamID01CannedResolutionForCall(callIndex int) string {
	switch callIndex {
	case 0: // triage / exam:scenario disposition
		// Resolves the finding — admin-user created deploy-svc-new during business
		// hours with a non-privileged Reader role.  Cites specific event IDs and
		// baseline frequency data so the judge awards reasoning_quality >= 3 and
		// investigation_thoroughness >= 3.
		return `I reviewed the finding fnd_shk_001 (New actor observed: deploy-svc-new).

Investigation steps:
1. Checked baseline: admin-user appears 5 times in azure:service_principal_created frequency table — this is a known pattern.
2. Reviewed evt_001: admin-user created deploy-svc-new at 14:22 UTC — business hours.
3. Reviewed evt_002: admin-user assigned Reader role to deploy-svc-new at 14:25 UTC — non-privileged role.
4. Confirmed admin-user has 63 prior interactions with sub-169efd95/resourceGroups/atom-rg (baseline relationship entry).

Assessment: This is standard cloud onboarding practice. The creating actor (admin-user) is deeply known and trusted (412 prior logins, 5 prior service principal creations). The new actor (deploy-svc-new) was created during business hours with a Reader-only role — non-escalated scope. No anomalous signals present.

Action: resolved
Conclusion: Benign onboarding. No further action required.`

	case 1: // judge / exam:judge disposition
		// The judge emits the verdict JSON line.
		return `{"finding_id":"fnd_shk_001","verdict":"pass","rubric":{"reasoning_quality":4,"investigation_thoroughness":4,"resolve_quality":4,"escalation_actionability":1},"rationale":"Analyst cited specific evidence: evt_001 (admin-user created deploy-svc-new at 14:22 business hours), evt_002 (Reader role assignment), and baseline frequency data (5 prior service principal creations by admin-user, 63 prior interactions with atom-rg). Systematic multi-step investigation cross-referenced events and baseline before concluding benign.","fix_target":"none"}`

	case 2: // report / exam:report disposition
		return `{"run_id":"test-R1","status":"complete","scenarios_processed":1}`

	default:
		return fmt.Sprintf(`{"finding_id":"fnd_shk_001","action":"resolved","reason":"Canned response for call %d"}`, callIndex)
	}
}
