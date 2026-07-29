// serve.go — `mallcop investigate --serve`: the long-running loop that reads
// questions from an inbox.jsonl and streams a trace to an outbox.jsonl, per
// docs/chat-investigate-protocol.md §2-3 (mallcop-pro repo).
//
// Scope note (mallcoppro-255 vs mallcoppro-067): this file implements the
// LOOP — read new inbox questions in order, run the real tool-calling Ask
// loop for each, stream ready/ack/tool_call/tool_result/answer/done/
// heartbeat/exit records to the outbox, and exit after an idle timeout. The
// FILE LAYOUT the protocol's §1 describes (a `sessions/<id>/` tree living on
// a dedicated git branch in the CUSTOMER's repo, with the browser dispatching
// a GHA job and polling the branch) is a transport/session-lifecycle concern
// refined by the sibling item mallcoppro-067. Serve here takes plain
// inbox/outbox file paths — whatever process wires those to the actual
// session directory (a GHA runner that `git pull`s the chat branch first, a
// laptop, a test) is free to do so without this package caring.
package investigate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/mallcop-app/mallcop/core/tools"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// genericServeErrMessage is the ONLY text that may ever reach the outbox
// (and therefore the customer repo's git history / the browser) in place of
// a real error. Internal error detail -- fs paths, model/lane routing,
// Forge/inference API responses (which can themselves embed credentials or
// account detail, see core/inference/direct.go's HTTP-status branch), or any
// other implementation-internal string -- must never cross the mailbox
// boundary. The full error is always logged to the runner's own stderr via
// logServeErr, which stays inside the GHA job log rather than the (public or
// shared) customer repo.
const genericServeErrMessage = "an internal error occurred"

// logServeErr logs the full error detail to the runner's own log (GHA job
// output), which never leaves this runner process -- the only place internal
// error detail is allowed to be observable.
func logServeErr(context string, err error) {
	log.Printf("investigate: %s: %v", context, err)
}

// Default tunables for Serve, matching the protocol doc.
const (
	DefaultIdleTimeout     = 90 * time.Second
	DefaultPollInterval    = 2 * time.Second
	DefaultHeartbeatPeriod = 20 * time.Second
)

// ServeOptions bundles Options (the Ask dependencies) with the inbox/outbox
// file paths and timing knobs for the --serve loop.
type ServeOptions struct {
	Options

	// InboxPath is the questions+control JSONL the caller (browser side)
	// appends to; Serve only ever reads it.
	InboxPath string
	// OutboxPath is the trace JSONL Serve appends to; Serve is the only
	// writer.
	OutboxPath string
	// RunnerID identifies this runner instance in ready/heartbeat/exit
	// records (e.g. a GHA run id). Defaults to "mallcop-investigate" when
	// empty.
	RunnerID string

	// IdleTimeout: after answering (or on boot, before the first question),
	// Serve exits once this much time has passed with no new question.
	// <= 0 uses DefaultIdleTimeout.
	IdleTimeout time.Duration
	// PollInterval is how often Serve re-reads the inbox for new records
	// while idle. <= 0 uses DefaultPollInterval.
	PollInterval time.Duration
	// HeartbeatPeriod is how often Serve appends a heartbeat record while
	// idle-waiting. <= 0 uses DefaultHeartbeatPeriod.
	HeartbeatPeriod time.Duration

	// Mailbox, when set, backs InboxPath/OutboxPath with a real git branch
	// (core/investigate/gitmailbox.go, mallcoppro-067): Serve calls
	// Mailbox.Pull() before each inbox read and Mailbox.Push(force) after
	// each outbox append, per protocol §4. Nil (the zero value) means plain
	// local files with no git operations at all -- every existing test in
	// this file, and laptop/local-only serve mode, are unaffected.
	Mailbox GitSyncer
}

func (o ServeOptions) runnerID() string {
	if o.RunnerID != "" {
		return o.RunnerID
	}
	return "mallcop-investigate"
}

func (o ServeOptions) idleTimeout() time.Duration {
	if o.IdleTimeout > 0 {
		return o.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (o ServeOptions) pollInterval() time.Duration {
	if o.PollInterval > 0 {
		return o.PollInterval
	}
	return DefaultPollInterval
}

func (o ServeOptions) heartbeatPeriod() time.Duration {
	if o.HeartbeatPeriod > 0 {
		return o.HeartbeatPeriod
	}
	return DefaultHeartbeatPeriod
}

// inboxRecord is the subset of inbox.jsonl fields Serve reads. Extra fields
// present on the wire (per the protocol doc) are ignored, not rejected.
//
// Findings carries the on-screen finding(s) the browser attached to a question
// (mallcoppro-010): the exact finding row the operator is asking about, so the
// runner seeds the analyst's initial context with it instead of starting blind
// and reverse-engineering a filter from the operator's prose. Absent on older
// browsers / the CLI path, in which case the loop behaves exactly as before.
type inboxRecord struct {
	Type     string          `json:"type"`
	Seq      int             `json:"seq"`
	ID       string          `json:"id"`
	Text     string          `json:"text"`
	Cmd      string          `json:"cmd"`
	Findings []SeededFinding `json:"findings"`
}

// Serve runs the --serve loop until: a control:shutdown record arrives, the
// idle timeout elapses with no new question, ctx is cancelled, or a fatal I/O
// error occurs on the outbox. It returns nil on every clean exit (idle,
// shutdown) — the caller distinguishes them by the exit record's reason field
// already written to the outbox, matching the CLI's "idle timeout is not a
// failure" contract. A returned error means the outbox/inbox themselves
// became unusable (not a question-processing failure, which is instead
// reported inline as an answer/tool error to keep the loop alive).
func Serve(ctx context.Context, opts ServeOptions) error {
	if opts.Client == nil {
		return fmt.Errorf("investigate: nil Client")
	}
	if opts.Store == nil {
		return fmt.Errorf("investigate: nil Store")
	}
	if opts.InboxPath == "" || opts.OutboxPath == "" {
		return fmt.Errorf("investigate: serve requires both InboxPath and OutboxPath")
	}

	// A re-dispatched runner (asleep→rewake, mallcoppro-ebef) appends to the
	// SAME sessions/<id>/ files its predecessor used, so both cursors must
	// resume from the files, not restart at zero: a restarted outbox seq is
	// silently dropped by the browser's `rec.seq <= live.outboxSeq` cursor,
	// and a restarted inbox cursor re-runs inference for every
	// already-answered question in the session.
	resumedOutboxSeq, resumedInboxSeq := resumeState(opts.InboxPath, opts.OutboxPath)

	ob := &outboxWriter{path: opts.OutboxPath, lastSeq: resumedOutboxSeq}
	if err := emit(ob, opts.Mailbox, map[string]any{"type": "ready", "runner": opts.runnerID(), "ts": nowRFC3339()}, true); err != nil {
		return err
	}

	lastSeq := resumedInboxSeq
	lastActivity := time.Now()
	lastHeartbeat := time.Time{}

	for {
		if err := ctx.Err(); err != nil {
			logServeErr("serve loop context error", err)
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "exit", "reason": "error", "detail": genericServeErrMessage, "ts": nowRFC3339()}, true)
			return nil
		}

		if opts.Mailbox != nil {
			if err := opts.Mailbox.Pull(); err != nil {
				return fmt.Errorf("investigate: pull inbox: %w", err)
			}
		}

		records, err := readInbox(opts.InboxPath)
		if err != nil {
			return fmt.Errorf("investigate: read inbox: %w", err)
		}

		progressed := false
		for _, rec := range records {
			if rec.Seq <= lastSeq {
				continue
			}
			lastSeq = rec.Seq
			progressed = true

			switch rec.Type {
			case "control":
				if rec.Cmd == "shutdown" {
					_ = emit(ob, opts.Mailbox, map[string]any{"type": "exit", "reason": "shutdown", "ts": nowRFC3339()}, true)
					return nil
				}
			case "question":
				handleQuestion(ctx, opts, ob, rec)
			}
			lastActivity = time.Now()
		}

		if progressed {
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "heartbeat", "runner": opts.runnerID(), "state": "idle", "ts": nowRFC3339()}, false)
			lastHeartbeat = time.Now()
			continue
		}

		if time.Since(lastActivity) >= opts.idleTimeout() {
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "exit", "reason": "idle", "ts": nowRFC3339()}, true)
			return nil
		}

		if time.Since(lastHeartbeat) >= opts.heartbeatPeriod() {
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "heartbeat", "runner": opts.runnerID(), "state": "idle", "ts": nowRFC3339()}, false)
			lastHeartbeat = time.Now()
		}

		select {
		case <-ctx.Done():
			logServeErr("serve loop context done", ctx.Err())
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "exit", "reason": "error", "detail": genericServeErrMessage, "ts": nowRFC3339()}, true)
			return nil
		case <-time.After(opts.pollInterval()):
		}
	}
}

// emit appends record to the outbox and, when mb is non-nil, syncs it to the
// git mailbox: force controls whether the push is immediate or coalesced
// per protocol §4 ("~1/s or on answer/done"). Callers pass force=true for
// ready/answer/done/exit (the records a browser is actively waiting on) and
// force=false for ack/tool_call/tool_result/heartbeat (fine to batch).
func emit(ob *outboxWriter, mb GitSyncer, record map[string]any, force bool) error {
	if err := ob.append(record); err != nil {
		return err
	}
	if mb == nil {
		return nil
	}
	if err := mb.Push(force); err != nil {
		return fmt.Errorf("investigate: push outbox: %w", err)
	}
	return nil
}

// handleQuestion runs one question through askCore with a hook that streams
// tool_call/tool_result trace records, then emits the answer + done records.
// A loop-level error (model/store failure) is reported as an "answer" record
// carrying the error text rather than killing the whole Serve session — one
// bad question should not take down a warm runner.
//
// The outbox is silent for the ENTIRE duration of askCore below unless the
// model happens to call a tool (tool_call/tool_result), which is exactly the
// gap that makes a long-thinking turn indistinguishable from a hard-killed
// runner (SIGKILL / evicted job — a graceful SIGTERM is handled elsewhere,
// mallcop#205): the browser's rewake watchdog only fires off an explicit
// "exit" record or an idle heartbeat, neither of which a still-running-but-
// silent handleQuestion ever produces. busyHeartbeats below closes that gap
// by appending a heartbeat/state:"busy" record on the SAME cadence as the
// idle heartbeat (DefaultHeartbeatPeriod / opts.heartbeatPeriod()) for as
// long as this question is in flight, so the mallcop-pro chat client's
// silence-based stall watchdog (chat_page.go) always sees a live record
// within one heartbeat period even mid-answer.
func handleQuestion(ctx context.Context, opts ServeOptions, ob *outboxWriter, rec inboxRecord) {
	_ = emit(ob, opts.Mailbox, map[string]any{"type": "ack", "q": rec.ID, "seq": rec.Seq, "ts": nowRFC3339()}, false)

	stopBusyHeartbeats := startBusyHeartbeats(ctx, opts, ob, rec.ID)
	defer stopBusyHeartbeats()

	hook := &traceHook{
		onToolCall: func(step int, name string, input any) {
			_ = emit(ob, opts.Mailbox, map[string]any{"type": "tool_call", "q": rec.ID, "step": step, "tool": name, "input": input}, false)
		},
		onToolResult: func(step int, name string, result any, err error) {
			trRec := map[string]any{"type": "tool_result", "q": rec.ID, "step": step, "tool": name, "summary": summarizeToolResult(name, result, err)}
			if out := toolResultOutput(result, err); out != nil {
				trRec["output"] = out
			}
			_ = emit(ob, opts.Mailbox, trRec, false)
		},
	}

	// Seed THIS question's loop with the on-screen finding(s) the browser attached
	// (mallcoppro-010). opts.Options is a value copy, so per-question seeding does
	// not leak across questions in a warm runner.
	askOpts := opts.Options
	askOpts.SeedFindings = rec.Findings

	res, err := askCore(ctx, askOpts, rec.Text, hook)
	if err != nil {
		logServeErr(fmt.Sprintf("askCore error for question %s", rec.ID), err)
		_ = emit(ob, opts.Mailbox, map[string]any{"type": "answer", "q": rec.ID, "text": "investigation failed: " + genericServeErrMessage, "citations": []Citation{}}, true)
		_ = emit(ob, opts.Mailbox, map[string]any{"type": "done", "q": rec.ID, "ts": nowRFC3339()}, true)
		return
	}

	citations := res.Citations
	if citations == nil {
		citations = []Citation{}
	}
	_ = emit(ob, opts.Mailbox, map[string]any{"type": "answer", "q": rec.ID, "text": res.Answer, "citations": citations}, true)
	_ = emit(ob, opts.Mailbox, map[string]any{"type": "done", "q": rec.ID, "ts": nowRFC3339()}, true)
}

// startBusyHeartbeats launches a ticker goroutine that appends a
// heartbeat/state:"busy" outbox record every opts.heartbeatPeriod() (the
// SAME named period as the main loop's idle heartbeat, DefaultHeartbeatPeriod
// — there is only one heartbeat cadence, idle and busy just carry a
// different "state") until the returned stop func is called. Serve's main
// loop only ever emits heartbeats while idle-waiting between questions
// (state:"idle"); this is the busy-side counterpart so a long askCore call
// still produces periodic proof of life. The ticker goroutine calls
// ob.append (via emit) concurrently with handleQuestion's own hook-driven
// emits on the same *outboxWriter — outboxWriter.append is mutex-protected
// specifically to make that safe (see outboxWriter.mu).
func startBusyHeartbeats(ctx context.Context, opts ServeOptions, ob *outboxWriter, qID string) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(opts.heartbeatPeriod())
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				_ = emit(ob, opts.Mailbox, map[string]any{"type": "heartbeat", "runner": opts.runnerID(), "state": "busy", "q": qID, "ts": nowRFC3339()}, false)
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// toolResultOutput carries the tool's raw structured *Output payload onto
// the outbox tool_result record (mallcoppro-00a, Gap A producer side).
// summarizeToolResult above renders a short human string for display, but
// the write-tools' propose-only payloads (recorddecisiontool.go
// RecordDecisionOutput{Proposed:...}, configtool.go/recordownedtool.go
// {RequiresConfirm:true}, selfexttool.go {Proposed:true}) live in the
// structured result itself, not in that string -- so a generic "<tool>
// returned N bytes" fallback silently drops them and the browser's
// Apply/Discard render (mallcoppro-573) has nothing to key off of. This
// marshals `result` to JSON and hands back a json.RawMessage so it embeds
// as a nested JSON object/array in the outbox record rather than as an
// escaped string. Returns nil (no "output" field at all) when there is no
// result to carry -- a tool error, or a marshal failure, both of which
// already have their failure text in "summary".
func toolResultOutput(result any, err error) any {
	if err != nil || result == nil {
		return nil
	}
	b, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil
	}
	return json.RawMessage(b)
}

// summarizeToolResult renders the short human trace string the protocol's
// tool_result.summary carries. The underlying data itself never leaves the
// runner beyond this summary and whatever the final answer chooses to quote.
func summarizeToolResult(name string, result any, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	switch name {
	case "search_events":
		if env, ok := result.(tools.SearchEventsEnvelope); ok {
			return fmt.Sprintf("%d event(s) matched", len(env.Events))
		}
	case "search_findings":
		if fs, ok := result.([]finding.Finding); ok {
			return fmt.Sprintf("%d finding(s) matched", len(fs))
		}
	case "check_baseline":
		if r, ok := result.(tools.CheckBaselineResult); ok {
			return fmt.Sprintf("known=%v frequency=%d", r.Known, r.Frequency)
		}
	case "lookup_rules":
		if r, ok := result.(tools.LookupRulesOutput); ok {
			return fmt.Sprintf("%d rule(s) matched", len(r.Rules))
		}
	case "run-eval":
		if r, ok := result.(RunEvalOutput); ok {
			return r.Summary
		}
	case "flag-like-this":
		if r, ok := result.(FlagLikeThisOutput); ok {
			return fmt.Sprintf("captured %s -> %s", r.ScenarioID, r.Path)
		}
	}
	// Generic fallback: marshal and report byte length only (never the
	// content itself, to honor "the underlying data stays in the runner").
	b, _ := json.Marshal(result)
	return fmt.Sprintf("%s returned %d bytes", name, len(b))
}

// resumeState scans a session's existing outbox/inbox files and returns the
// cursors a resumed runner must continue from:
//
//   - outboxSeq: the max outbox seq already written, so this runner's records
//     extend the file's single monotonic seq line (protocol §4). The browser
//     keys its dedup cursor on that line; a counter restarting at 1 makes
//     every record of the resumed runner invisible to it (mallcoppro-ebef).
//   - inboxSeq: the highest inbox seq whose question already has a "done"
//     record. Questions at or below it are answered and must not re-run
//     inference; a question acked but never done'd (predecessor died
//     mid-answer) stays above the cursor and IS re-processed.
//
// The join is by question id (done.q -> inbox record ID), not by the ack's
// seq field: outboxWriter.append overwrites every record's "seq" with the
// outbox counter, so an inbox seq can never be recovered from the outbox.
// A fresh session (no outbox file yet) resumes from (0, 0), which is exactly
// the old fixed behavior.
func resumeState(inboxPath, outboxPath string) (outboxSeq, inboxSeq int) {
	f, err := os.Open(outboxPath)
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	type outboxRecord struct {
		Type string `json:"type"`
		Q    string `json:"q"`
		Seq  int    `json:"seq"`
	}
	done := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec outboxRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.Seq > outboxSeq {
			outboxSeq = rec.Seq
		}
		if rec.Type == "done" && rec.Q != "" {
			done[rec.Q] = true
		}
	}

	if len(done) == 0 {
		return outboxSeq, 0
	}
	records, err := readInbox(inboxPath)
	if err != nil {
		return outboxSeq, 0
	}
	for _, rec := range records {
		if rec.Type == "question" && done[rec.ID] && rec.Seq > inboxSeq {
			inboxSeq = rec.Seq
		}
	}
	return outboxSeq, inboxSeq
}

// readInbox reads and parses every well-formed line of path. A missing file
// is treated as "no records yet" (the browser side may not have written the
// first question at boot time). Malformed lines are skipped rather than
// failing the whole read — the browser is the sole writer and Serve must
// tolerate a partially-flushed trailing line during a concurrent append.
func readInbox(path string) ([]inboxRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []inboxRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec inboxRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// outboxWriter appends JSON-line trace records to a single file. Serve
// itself is still the only PROCESS writing this file (per the protocol's
// single-writer-per-file rule) — but as of the busy-heartbeat ticker
// (startBusyHeartbeats), it is no longer the only GOROUTINE: the ticker
// appends heartbeat/state:"busy" records concurrently with handleQuestion's
// own hook-driven tool_call/tool_result/answer/done appends on the same
// *outboxWriter, and Serve's main loop can itself still be mid-append when
// the ticker fires. append is therefore NOT safe to call from multiple
// goroutines without mu: two concurrent appends could interleave their
// f.Write calls (O_APPEND only guarantees atomicity per write(2) syscall,
// not across the read-modify-write of lastSeq + marshal + write done here)
// or hand out the same "seq" value twice. mu serializes the whole
// increment-marshal-write sequence so every append is atomic with respect
// to every other one, from any goroutine.
//
// It also assigns the record's "seq" field: protocol §4 states "seq is
// monotonic per file per session: browser assigns inbox seq, runner assigns
// outbox seq" -- every record this process appends (not just
// questions/answers) gets the next outbox seq, so a browser resuming a poll
// can cursor the outbox exactly like the runner cursors the inbox.
type outboxWriter struct {
	path    string
	lastSeq int
	mu      sync.Mutex
}

func (w *outboxWriter) append(record map[string]any) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastSeq++
	record["seq"] = w.lastSeq
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("investigate: marshal outbox record: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("investigate: open outbox: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("investigate: write outbox: %w", err)
	}
	return nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
