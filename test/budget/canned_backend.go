//go:build e2e

// Package budget contains the chain budget enforcement integration test.
//
// canned_backend.go — tiny Go HTTP server that mimics Forge's
// /v1/chat/completions endpoint and returns fixed token counts so the
// budget test has deterministic arithmetic.
package budget

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

// CannedBackend is a minimal HTTP server that mimics Forge's
// /v1/chat/completions endpoint.  Each request is recorded and a fixed
// token count is returned so budget tests can predict exact totals.
type CannedBackend struct {
	// TokensPerResponse is the total token count (input+output) reported in
	// each response's usage field.  4000 by default; change before Start().
	TokensPerResponse int

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

	// Split tokens roughly 80/20 input/output — the exact split doesn't matter
	// for budget accounting since we track the total.
	inputTokens := int(float64(b.TokensPerResponse) * 0.8)
	outputTokens := b.TokensPerResponse - inputTokens

	// Embed a canned triage/investigate/heal resolution in the response text
	// so that if the `we` orchestrator tries to parse output, it gets a valid
	// JSON payload.
	step := b.CallCount() // 1-indexed after record() incremented callCount
	callIndex := step - 1
	cannedContent := cannedResolutionForCall(callIndex)

	resp := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-canned-%04d", step),
		"object":  "chat.completion",
		"model":   "claude-sonnet-4-5-20250514",
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
	cannedContent := cannedResolutionForCall(callIndex)

	resp := map[string]interface{}{
		"id":    fmt.Sprintf("msg-canned-%04d", step),
		"type":  "message",
		"role":  "assistant",
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

// cannedResolutionForCall returns a deterministic JSON resolution payload for
// the nth inference call (0-indexed):
//   - call 0 (triage):      action=escalate → triggers investigate
//   - call 1 (investigate): action=escalate → triggers heal
//   - call 2 (heal):        action=remediate (should never be reached if budget gate fires)
func cannedResolutionForCall(callIndex int) string {
	switch callIndex {
	case 0: // triage
		return `{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned triage: unrecognized actor from unknown geo. Escalating for investigation."}`
	case 1: // investigate
		return `{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned investigate: confirmed credential stuffing from Tor exit node. Escalating to heal.","confidence":0.95}`
	case 2: // heal (should not be reached when budget gate fires)
		return `{"finding_id":"budget-test-finding-001","proposed_action":"disable-account","target":"test-attacker","reason":"Canned heal: disable account to stop ongoing attack.","gate":"pending"}`
	default:
		return fmt.Sprintf(`{"finding_id":"budget-test-finding-001","action":"escalate","reason":"Canned response for call %d"}`, callIndex)
	}
}
