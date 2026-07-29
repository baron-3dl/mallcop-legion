package investigate

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/inference"
)

// readOutboxTypes reads path (which may not exist yet) and returns the
// "type" field of every well-formed JSONL record, in order.
func readOutboxTypes(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open outbox: %v", err)
	}
	defer f.Close()
	var types []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if tp, ok := rec["type"].(string); ok {
			types = append(types, tp)
		}
	}
	return types
}

// TestServe_QuestionFlowThenIdleExit drives `mallcop investigate --serve`
// end-to-end against a real inbox/outbox file pair, a real store, and the
// same scripted-HTTP-transport double used by the Ask test (the LLM
// transport is the only stub — see test_decisions). It proves: a question
// appended to the inbox produces ack/tool_call/tool_result/answer/done
// records naming the real seeded event, and the runner exits with reason
// "idle" once the idle timeout elapses with no further questions — bounding
// GHA-minute burn per the protocol doc.
func TestServe_QuestionFlowThenIdleExit(t *testing.T) {
	st := seedStore(t)
	bl := seedBaseline(t)
	srv, _ := scriptedServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	question := map[string]any{"type": "question", "seq": 1, "id": "q_1", "text": "What has ghost been doing?"}
	line, _ := json.Marshal(question)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st, Baseline: bl},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour, // don't let heartbeats crowd the assertions below
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	types := readOutboxTypes(t, outboxPath)
	wantPrefix := []string{"ready", "ack", "tool_call", "tool_result", "answer", "done"}
	if len(types) < len(wantPrefix) {
		t.Fatalf("outbox has %d records %v, want at least %d starting with %v", len(types), types, len(wantPrefix), wantPrefix)
	}
	for i, want := range wantPrefix {
		if types[i] != want {
			t.Fatalf("outbox record %d type = %q, want %q (full sequence: %v)", i, types[i], want, types)
		}
	}
	last := types[len(types)-1]
	if last != "exit" {
		t.Fatalf("last outbox record type = %q, want exit (idle timeout)", last)
	}

	// The answer record must carry the real cited event id, not a placeholder.
	raw, err := os.ReadFile(outboxPath)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if !strings.Contains(string(raw), "evt-ghost-001") {
		t.Fatalf("outbox never mentions the real seeded event id evt-ghost-001:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"reason":"idle"`) {
		t.Fatalf("exit record did not carry reason idle:\n%s", raw)
	}
}

// answeringServer is a minimal REAL httptest transport whose every response is
// a direct end_turn answer — no tool round-trips — so multi-question and
// multi-run (resume) serve tests don't depend on scriptedServer's fixed
// two-call script.
func answeringServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content":     []map[string]any{{"type": "text", "text": "the answer."}},
		})
	}))
}

// readOutboxRecords reads every well-formed JSONL record of path, in order.
func readOutboxRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	defer f.Close()
	var recs []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		recs = append(recs, rec)
	}
	return recs
}

// serveOnce runs one full Serve lifecycle (fresh ServeOptions, as a fresh
// GHA runner process would) against the shared inbox/outbox pair.
func serveOnce(t *testing.T, srvURL, inboxPath, outboxPath string) {
	t.Helper()
	st := seedStore(t)
	client := &inference.DirectClient{BaseURL: srvURL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}
}

// appendInboxLine appends one JSONL record to the inbox, as the browser does.
func appendInboxLine(t *testing.T, inboxPath string, rec map[string]any) {
	t.Helper()
	line, _ := json.Marshal(rec)
	f, err := os.OpenFile(inboxPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open inbox: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatalf("append inbox: %v", err)
	}
}

// TestServe_ResumeContinuesOutboxSeqAndSkipsAnsweredQuestions is the
// mallcoppro-ebef regression: a re-dispatched runner (asleep→rewake) appends
// to the SAME session files, so it must (a) continue the outbox's single
// monotonic seq line — the browser dedups with `rec.seq <= live.outboxSeq`
// and silently drops a restarted counter's records — and (b) not re-run
// inference for questions that already have a done record.
func TestServe_ResumeContinuesOutboxSeqAndSkipsAnsweredQuestions(t *testing.T) {
	srv := answeringServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	// Run 1: q_1 arrives, is answered, runner idle-exits.
	appendInboxLine(t, inboxPath, map[string]any{"type": "question", "seq": 1, "id": "q_1", "text": "first?"})
	serveOnce(t, srv.URL, inboxPath, outboxPath)

	// Between runs: the operator's next question lands after the idle exit
	// (the ebef timeline), and the browser re-dispatches a fresh runner.
	appendInboxLine(t, inboxPath, map[string]any{"type": "question", "seq": 2, "id": "q_2", "text": "second?"})
	serveOnce(t, srv.URL, inboxPath, outboxPath)

	recs := readOutboxRecords(t, outboxPath)

	// The whole file — both runs — must be one strictly increasing seq line.
	prev := 0
	for i, rec := range recs {
		seq, ok := rec["seq"].(float64)
		if !ok {
			t.Fatalf("outbox record %d has no numeric seq: %v", i, rec)
		}
		if int(seq) != prev+1 {
			t.Fatalf("outbox seq line broken at record %d: got %d after %d (a browser cursor at %d would drop this record) — records: %v", i, int(seq), prev, prev, recs)
		}
		prev = int(seq)
	}

	// q_1 answered exactly once (no replay storm), q_2 answered by run 2.
	answers := map[string]int{}
	for _, rec := range recs {
		if rec["type"] == "answer" {
			q, _ := rec["q"].(string)
			answers[q]++
		}
	}
	if answers["q_1"] != 1 {
		t.Fatalf("q_1 answered %d time(s), want exactly 1 (resume must not re-run answered questions): %v", answers["q_1"], recs)
	}
	if answers["q_2"] != 1 {
		t.Fatalf("q_2 answered %d time(s), want exactly 1: %v", answers["q_2"], recs)
	}
}

// TestServe_ResumeReprocessesAckedButUnansweredQuestion: a predecessor that
// died MID-answer left an ack but no done for q_2. The resumed runner must
// re-process q_2 (the customer never got an answer) while still skipping the
// done'd q_1 — the join is done-records-by-question-id, not acks.
func TestServe_ResumeReprocessesAckedButUnansweredQuestion(t *testing.T) {
	srv := answeringServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	appendInboxLine(t, inboxPath, map[string]any{"type": "question", "seq": 1, "id": "q_1", "text": "first?"})
	appendInboxLine(t, inboxPath, map[string]any{"type": "question", "seq": 2, "id": "q_2", "text": "second?"})

	// Hand-write the dead predecessor's outbox: q_1 fully answered, q_2
	// acked and then silence (killed mid-answer, no done, no exit).
	for _, rec := range []map[string]any{
		{"type": "ready", "seq": 1},
		{"type": "ack", "q": "q_1", "seq": 2},
		{"type": "answer", "q": "q_1", "text": "done already.", "seq": 3},
		{"type": "done", "q": "q_1", "seq": 4},
		{"type": "ack", "q": "q_2", "seq": 5},
	} {
		line, _ := json.Marshal(rec)
		f, err := os.OpenFile(outboxPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("open outbox: %v", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("seed outbox: %v", err)
		}
		f.Close()
	}

	serveOnce(t, srv.URL, inboxPath, outboxPath)

	recs := readOutboxRecords(t, outboxPath)
	answers := map[string]int{}
	maxSeq := 0
	for _, rec := range recs {
		if rec["type"] == "answer" {
			q, _ := rec["q"].(string)
			answers[q]++
		}
		if seq, ok := rec["seq"].(float64); ok && int(seq) > maxSeq {
			maxSeq = int(seq)
		}
	}
	if answers["q_1"] != 1 {
		t.Fatalf("q_1 answered %d time(s) total, want exactly 1 (it already had a done record): %v", answers["q_1"], recs)
	}
	if answers["q_2"] != 1 {
		t.Fatalf("q_2 answered %d time(s), want exactly 1 (acked-but-not-done must be re-processed): %v", answers["q_2"], recs)
	}
	// The resumed run's records must continue past the predecessor's seq 5.
	if maxSeq <= 5 {
		t.Fatalf("resumed runner never advanced the outbox seq past the predecessor's high-water 5 (max=%d): %v", maxSeq, recs)
	}
}

// erroringServer is a REAL httptest.Server that always answers /v1/messages
// with an HTTP 500 whose body embeds sentinel — standing in for whatever
// internal detail a real failure could leak (a Bedrock/Forge error body, a
// filesystem path, a model/lane routing decision). inference.DirectClient
// (core/inference/direct.go) folds that body verbatim into the Go error text
// it returns (`"inference: %s returned HTTP %d: %s"`), so this is the REAL
// code path a leaked secret would travel — not a hand-rolled fake error.
func erroringServer(t *testing.T, sentinel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(sentinel))
	}))
}

// TestServe_AnswerRecordSanitizesInternalErrorDetail is the mallcoppro-c32
// regression test for boundary fix (1): when askCore fails (here, because the
// real inference transport got back an HTTP 500 whose body carries
// secret-like internal detail), the outbox "answer" record Serve emits must
// NOT contain that detail — only a generic natural-language message. The full
// error must still make it somewhere useful for operators (the runner's own
// log), just never across the mailbox boundary into the customer repo's git
// history or the browser.
func TestServe_AnswerRecordSanitizesInternalErrorDetail(t *testing.T) {
	const sentinel = "SECRET_FORGE_API_KEY_sk-mallcop-t0p-s3cr3t-9f8e7d"

	st := seedStore(t)
	srv := erroringServer(t, sentinel)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	question := map[string]any{"type": "question", "seq": 1, "id": "q_1", "text": "What has ghost been doing?"}
	line, _ := json.Marshal(question)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	raw, err := os.ReadFile(outboxPath)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	out := string(raw)

	if strings.Contains(out, sentinel) {
		t.Fatalf("outbox leaked the internal error sentinel across the mailbox boundary:\n%s", out)
	}
	if !strings.Contains(out, "an internal error occurred") {
		t.Fatalf("outbox answer record does not carry the generic error message:\n%s", out)
	}

	types := readOutboxTypes(t, outboxPath)
	foundAnswer := false
	for _, ty := range types {
		if ty == "answer" {
			foundAnswer = true
		}
	}
	if !foundAnswer {
		t.Fatalf("outbox never got an answer record for the failed question: %v", types)
	}
}

// TestServe_ShutdownControlRecordExitsImmediately proves a control:shutdown
// record ends the session with reason "shutdown" rather than waiting out the
// idle timeout — the protocol's "user closed chat" path.
func TestServe_ShutdownControlRecordExitsImmediately(t *testing.T) {
	st := seedStore(t)
	srv, _ := scriptedServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	ctrl := map[string]any{"type": "control", "seq": 1, "cmd": "shutdown"}
	line, _ := json.Marshal(ctrl)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:      Options{Client: client, Model: "test-model", Store: st},
		InboxPath:    inboxPath,
		OutboxPath:   outboxPath,
		IdleTimeout:  time.Hour, // would hang the test if shutdown didn't short-circuit it
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	types := readOutboxTypes(t, outboxPath)
	if len(types) != 2 || types[0] != "ready" || types[1] != "exit" {
		t.Fatalf("outbox types = %v, want [ready exit]", types)
	}
	raw, _ := os.ReadFile(outboxPath)
	if !strings.Contains(string(raw), `"reason":"shutdown"`) {
		t.Fatalf("exit record did not carry reason shutdown:\n%s", raw)
	}
}

// TestOutboxWriter_ConcurrentAppendIsRaceSafe is the mallcoppro-cea
// regression test for the busy-heartbeat ticker's concurrency requirement:
// startBusyHeartbeats' goroutine calls ob.append (via emit) concurrently
// with handleQuestion's own hook-driven appends on the SAME *outboxWriter.
// Before outboxWriter.mu was added, append's read-modify-write of lastSeq
// plus its os.OpenFile/Write was not safe for concurrent callers — this
// drives many goroutines at the same writer at once and, under `go test
// -race`, proves there is no data race; it also proves the OBSERVABLE
// correctness property that matters to the protocol: every append survives
// (no lost writes) and the assigned "seq" values are a gapless permutation
// of 1..n with no duplicates (the browser's outbox cursor depends on a
// strictly monotonic, contiguous seq line).
func TestOutboxWriter_ConcurrentAppendIsRaceSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outbox.jsonl")
	ob := &outboxWriter{path: path}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := ob.append(map[string]any{"type": "heartbeat", "state": "busy", "i": i}); err != nil {
				t.Errorf("concurrent append %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	recs := readOutboxRecords(t, path)
	if len(recs) != n {
		t.Fatalf("outbox has %d records, want %d (a lost write means the mutex is not protecting the append)", len(recs), n)
	}
	seen := make(map[int]bool, n)
	for _, rec := range recs {
		seqF, ok := rec["seq"].(float64)
		if !ok {
			t.Fatalf("record missing numeric seq: %v", rec)
		}
		seq := int(seqF)
		if seen[seq] {
			t.Fatalf("seq %d assigned twice — concurrent appends raced on lastSeq: %v", seq, recs)
		}
		seen[seq] = true
	}
	for i := 1; i <= n; i++ {
		if !seen[i] {
			t.Fatalf("seq line has a gap: never saw seq %d among %d records: %v", i, n, recs)
		}
	}
}

// slowAnsweringServer is a REAL httptest.Server (the same "the LLM transport
// is the only stub" boundary as scriptedServer/answeringServer above) that
// sleeps for delay before returning a plain end_turn answer — standing in
// for a genuinely slow model turn, so handleQuestion's askCore call stays in
// flight long enough to observe the busy-heartbeat ticker actually tick.
func slowAnsweringServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content":     []map[string]any{{"type": "text", "text": "the answer."}},
		})
	}))
}

// TestHandleQuestion_EmitsBusyHeartbeatsDuringASlowAnswer is the fix's own
// regression test for the silent-outbox gap: before this fix, the outbox
// produced NOTHING between "ack" and "answer" for a question that never
// called a tool, no matter how long askCore took — indistinguishable from a
// hard-killed runner from the browser's point of view. With HeartbeatPeriod
// set well below the (stubbed, but genuinely slow) model turn's duration,
// handleQuestion must append at least two heartbeat/state:"busy" records —
// each carrying this question's id — while the answer is still in flight.
func TestHandleQuestion_EmitsBusyHeartbeatsDuringASlowAnswer(t *testing.T) {
	st := seedStore(t)
	const heartbeatPeriod = 25 * time.Millisecond
	const answerDelay = 220 * time.Millisecond // not a clean multiple of heartbeatPeriod
	srv := slowAnsweringServer(t, answerDelay)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	question := map[string]any{"type": "question", "seq": 1, "id": "q_slow", "text": "What has ghost been doing?"}
	line, _ := json.Marshal(question)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: heartbeatPeriod,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	recs := readOutboxRecords(t, outboxPath)

	ackIdx, answerIdx := -1, -1
	busyHeartbeats := 0
	for i, rec := range recs {
		switch rec["type"] {
		case "ack":
			if ackIdx == -1 {
				ackIdx = i
			}
		case "answer":
			if answerIdx == -1 {
				answerIdx = i
			}
		case "heartbeat":
			if rec["state"] != "busy" {
				continue
			}
			if rec["q"] != "q_slow" {
				t.Fatalf("busy heartbeat record %d missing/wrong q field (want q_slow): %v", i, rec)
			}
			if ackIdx == -1 {
				t.Fatalf("busy heartbeat record %d appeared before the question's ack record: %v", i, recs)
			}
			busyHeartbeats++
		}
	}
	if ackIdx == -1 {
		t.Fatalf("outbox never got an ack record for q_slow: %v", recs)
	}
	if answerIdx == -1 {
		t.Fatalf("outbox never got an answer record for q_slow: %v", recs)
	}
	if busyHeartbeats < 2 {
		t.Fatalf("got %d busy heartbeat(s) during a %v-long answer with a %v heartbeat period, want >= 2: %v",
			busyHeartbeats, answerDelay, heartbeatPeriod, recs)
	}
}

// recordDecisionScriptedServer is a REAL httptest transport (mirrors
// scriptedServer in investigate_test.go) whose scripted turn 1 requests the
// record_decision tool (op=suppress) instead of search_events, then answers
// with a text turn once it sees the real tool_result. This is the ONLY
// stubbed layer: the tool itself (recordDecisionTool), the config load
// (propose-only default, no mallcop.yaml on disk), and the outbox-writing
// serve loop are all real production code.
func recordDecisionScriptedServer(t *testing.T) *httptest.Server {
	t.Helper()
	var calls int
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":        "message",
				"role":        "assistant",
				"stop_reason": "tool_use",
				"content": []map[string]any{
					{
						"type": "tool_use",
						"id":   "toolu_rd_001",
						"name": "record_decision",
						"input": map[string]any{
							"op":      "suppress",
							"pattern": "github/login/ghost",
							"reason":  "known automation account",
						},
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content":     []map[string]any{{"type": "text", "text": "proposed a suppress directive; approve to apply."}},
		})
	}))
}

// TestHandleQuestion_ToolResultRecordCarriesToolAndStructuredOutput is the
// mallcoppro-00a enforcement test (Gap A producer side): a record_decision
// call at the propose-only autonomy dial (config.AutonomyNon, the default —
// no mallcop.yaml is written for this test's RepoRoot, so config.LoadEffective
// falls back to Defaults()) must emit a tool_result outbox record carrying
// BOTH "tool" == "record_decision" and a structured "output" object whose
// "proposed" field is present -- the exact two fields mallcop-pro's
// chat_page.go Apply/Discard render (mallcoppro-573) keys off of. Before this
// fix, onToolResult only emitted {type,q,step,summary}; summary for this tool
// falls through summarizeToolResult's generic "<tool> returned N bytes"
// fallback, which carries no machine-readable payload at all.
func TestHandleQuestion_ToolResultRecordCarriesToolAndStructuredOutput(t *testing.T) {
	st := seedStore(t)
	srv := recordDecisionScriptedServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")
	// repoRoot is a bare tmp dir with no mallcop.yaml on disk, so
	// record_decision's config.LoadEffective(override) resolves via Load's
	// os.ErrNotExist branch to config.Defaults() -- Learning.Autonomy ==
	// config.AutonomyNon -- deterministically, regardless of where the test
	// binary happens to run from.
	repoRoot := t.TempDir()

	question := map[string]any{"type": "question", "seq": 1, "id": "q_decide", "text": "suppress ghost's known automation logins"}
	line, _ := json.Marshal(question)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st, RepoRoot: repoRoot},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	recs := readOutboxRecords(t, outboxPath)
	var toolResult map[string]any
	for _, rec := range recs {
		if rec["type"] == "tool_result" {
			toolResult = rec
			break
		}
	}
	if toolResult == nil {
		t.Fatalf("outbox never got a tool_result record: %v", recs)
	}
	if toolResult["tool"] != "record_decision" {
		t.Fatalf(`tool_result record "tool" = %v, want "record_decision": %v`, toolResult["tool"], toolResult)
	}
	output, ok := toolResult["output"].(map[string]any)
	if !ok {
		t.Fatalf(`tool_result record "output" = %v (%T), want a structured object: %v`, toolResult["output"], toolResult["output"], toolResult)
	}
	if output["applied"] != false {
		t.Fatalf(`tool_result output "applied" = %v, want false (propose-only dial must not commit): %v`, output["applied"], output)
	}
	proposed, ok := output["proposed"].(map[string]any)
	if !ok {
		t.Fatalf(`tool_result output "proposed" = %v (%T), want the structured ProposedDirective payload: %v`, output["proposed"], output["proposed"], output)
	}
	if proposed["op"] != "suppress" || proposed["pattern"] != "github/login/ghost" {
		t.Fatalf(`tool_result output "proposed" = %v, want op=suppress pattern=github/login/ghost`, proposed)
	}

	// summary stays populated too (backward-compat) -- this fix only ADDS
	// tool/output, it never removes the pre-existing summary field.
	if s, _ := toolResult["summary"].(string); s == "" {
		t.Fatalf("tool_result record lost its summary field: %v", toolResult)
	}
}
