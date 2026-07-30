package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Directive is an operator-steering record on the directives stream. It is
// FIRST-CLASS: a directive appended by one process is loaded and obeyed by the
// next process that Opens the same repo. The scan pipeline calls LoadDirectives
// at startup and applies each directive (e.g. suppressing findings whose source
// or reason matches Pattern) before emitting results.
//
// Op is the verb the consumer dispatches on. The store does not interpret it —
// it only persists and replays — but the canonical vocabulary is:
//
//	suppress  — drop findings matching Pattern
//	focus     — prioritize findings matching Pattern
//	mute       — silence notifications for Pattern
//	unsuppress — cancel a prior suppress for Pattern
//
// Pattern is the target the op applies to (a finding type, source, actor glob,
// or substring — the consumer decides matching semantics). Reason is the
// human/agent rationale, preserved for audit. Meta carries op-specific extra
// fields without schema churn — see DirectiveMeta for the documented shape.
type Directive struct {
	Op      string          `json:"op"`
	Pattern string          `json:"pattern,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Actor   string          `json:"actor,omitempty"` // who issued it (operator/agent)
	Meta    json.RawMessage `json:"meta,omitempty"`
}

// DirectiveMeta is the documented (but NOT schema-enforced) shape of
// Directive.Meta. Keeping Meta as json.RawMessage on the wire means adding a
// field here is never a store schema change — old records simply omit the new
// key and Unmarshal leaves it at its zero value. Consumers registered on the
// pipeline's DirectiveDispatcher (core/pipeline/directives.go) parse the
// fields they care about via Directive.ParseMeta; a consumer MUST tolerate a
// zero value for every field (an absent key, not an error).
//
//	expires_at  — RFC3339 timestamp; the directive auto-expires on replay past
//	              this instant (mute's TTL — see Gap C, mallcoppro-ce6).
//	severity    — override for finding.Severity (the severity consumer).
//	weight      — attention weight fed to finding ranking / inquest depth
//	              budget (focus / watch-closer).
//	target_kind — what Pattern names: "finding-key" (source/type/actor triple,
//	              the default matchPattern semantics), "gap-key", or "source".
type DirectiveMeta struct {
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Weight     float64   `json:"weight,omitempty"`
	TargetKind string    `json:"target_kind,omitempty"`
}

// ParseMeta decodes Directive.Meta into its documented shape. An empty/nil
// Meta decodes to the zero DirectiveMeta and no error — a directive issued
// before a given Meta field existed is valid, not malformed.
func (d Directive) ParseMeta() (DirectiveMeta, error) {
	var m DirectiveMeta
	if len(d.Meta) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(d.Meta, &m); err != nil {
		return DirectiveMeta{}, fmt.Errorf("store: decode directive meta: %w", err)
	}
	return m, nil
}

// Turn is one entry on the conversation stream — the durable agent-loop
// transcript. It is FIRST-CLASS alongside directives: the agent loop appends a
// Turn per exchange and replays the whole conversation on the next Open so a
// respawned session resumes with full context.
//
// Role is "user", "assistant", "system", or "tool". Content is the message
// text. ToolName/ToolInput/ToolResult are populated for tool turns. Meta is
// open for model/usage annotations.
type Turn struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	ToolInput  json.RawMessage `json:"tool_input,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
	Meta       json.RawMessage `json:"meta,omitempty"`
}

// LoadDirectives replays the directives stream into typed Directive records,
// oldest first. This is the call the scan pipeline makes at startup to obey
// operator steering written in a prior process. A repo that has never had a
// directive appended returns an empty slice (not an error).
func (s *Store) LoadDirectives() ([]Directive, error) {
	raws, err := s.Load(KindDirectives)
	if err != nil {
		return nil, err
	}
	out := make([]Directive, 0, len(raws))
	for i, raw := range raws {
		var d Directive
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("store: decode directive %d: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// LoadConversation replays the conversation stream into typed Turn records,
// oldest first — the durable transcript the agent loop resumes from.
func (s *Store) LoadConversation() ([]Turn, error) {
	raws, err := s.Load(KindConversation)
	if err != nil {
		return nil, err
	}
	out := make([]Turn, 0, len(raws))
	for i, raw := range raws {
		var t Turn
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("store: decode turn %d: %w", i, err)
		}
		out = append(out, t)
	}
	return out, nil
}

// ScanRecord is one entry on the scans stream (mallcoppro-e3c): a durable,
// rotation-surviving register of every completed `mallcop scan` run — appended
// by core/pipeline.Run at the end of EVERY run, findings or not. It is the
// authoritative source detection-time investigation's scan-schedule
// correlation reads first (CommitTimesFor is the historical fallback for scan
// times that predate this stream).
type ScanRecord struct {
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	EventsScanned    int       `json:"events_scanned"`
	FindingsDetected int       `json:"findings_detected"`
	Escalated        int       `json:"escalated"`
	MallcopVersion   string    `json:"mallcop_version,omitempty"`
}

// LoadScans replays the scans stream into typed ScanRecord records, oldest
// first. A store that has never completed a scan (or predates KindScans)
// returns an empty slice, not an error.
func (s *Store) LoadScans() ([]ScanRecord, error) {
	raws, err := s.Load(KindScans)
	if err != nil {
		return nil, err
	}
	out := make([]ScanRecord, 0, len(raws))
	for i, raw := range raws {
		var r ScanRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("store: decode scan record %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// SelfextDispatchRecord is one entry on the selfext_dispatches stream
// (mallcoppro-0d95, Design §Gap A): a durable request to run mallcop's
// self-extension engine (`mallcop selfext --run`/`--propose`), appended by the
// investigating model's `dispatch_selfext` chat tool when the operator's
// autonomy dial reads "semi" or "fully" (an "auto" read — see
// core/investigate/selfexttool.go). A "non"/propose-only read never appends a
// record: the tool returns a `{proposed:...}` result to the model instead, so
// this stream contains ONLY dispatches that were actually authorized to run.
//
// This is the durable record the privileged mallcop-pro side later consumes
// to actually kick off the authoring run (e.g. a workflow_dispatch) — the
// chat loop itself never makes that call (core/investigate is
// net/http-banned; see imports_test.go). Fields mirror the CLI's own
// `mallcop selfext --run` gap-description flags (cli/selfext.go's runArgs) so
// a consumer can build the equivalent CLI invocation directly from a record.
type SelfextDispatchRecord struct {
	RequestedAt time.Time `json:"requested_at"`
	// Lane is the authoring lane requested, e.g. "heal" or "investigate" —
	// mirrors `mallcop selfext --run --lane`.
	Lane string `json:"lane"`
	// DetectorID, EventType, TargetFamily, Severity, Actor, Source describe
	// the detection gap to author against — mirrors `mallcop selfext --run`'s
	// --detector-id/--event-type/--target-family/--severity/--actor/--source.
	DetectorID   string `json:"detector_id,omitempty"`
	EventType    string `json:"event_type,omitempty"`
	TargetFamily string `json:"target_family,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Actor        string `json:"actor,omitempty"`
	Source       string `json:"source,omitempty"`
	// Reason is the model's rationale for the dispatch, preserved for audit
	// (mirrors Directive.Reason's role on the directives stream).
	Reason string `json:"reason,omitempty"`
	// Autonomy is the dial reading that authorized this commit ("semi" or
	// "fully" — never "non", since a "non" read never appends a record).
	Autonomy string `json:"autonomy"`
}

// LoadSelfextDispatches replays the selfext_dispatches stream into typed
// SelfextDispatchRecord records, oldest first. A store that predates
// KindSelfextDispatches, or has never had an authorized dispatch, returns an
// empty slice, not an error — mirrors LoadScans/LoadDirectives' contract.
func (s *Store) LoadSelfextDispatches() ([]SelfextDispatchRecord, error) {
	raws, err := s.Load(KindSelfextDispatches)
	if err != nil {
		return nil, err
	}
	out := make([]SelfextDispatchRecord, 0, len(raws))
	for i, raw := range raws {
		var r SelfextDispatchRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("store: decode selfext dispatch record %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// GrantOutcome is one entry on the grants stream (mallcoppro-62b, Design §4
// corpus mechanics): a permission-diagnosis row for the customer-operable
// onboarding loop's "connector can't read this source, here's the exact
// remediate command" flow.
//
// A row is EITHER a GRANT-MISS (the diagnosis of a failed access attempt:
// Connector/Cloud/AccessMode/FailureClass/GrantCommand populated, Resolved
// false, ResolvedRef empty) OR a RESOLUTION of a prior miss (Resolved true,
// ResolvedRef set to identify the original miss row). A resolution is ALWAYS
// a SECOND appended row — never a mutation of the first. This is the same
// append-only discipline KindFindings/its resolutions stream already uses:
// the miss and its resolution are two facts in history, not one fact edited
// in place, so `git log` shows exactly what was diagnosed and when it was
// fixed rather than overwriting the diagnosis.
//
// This stream is the in-product accretion loop's memory, not a system of
// record for remediation scripts: a `grants/<connector>.sh` helper is only
// ever a DERIVED artifact rendered from this stream, never itself the
// source of truth (two-writers is rejected — see the design ruling this
// item cites, R5). It is PRIVATE per-tenant history: it lives solely in the
// customer's own git repo, with no R8 shared-corpus contribute-back
// machinery attached.
type GrantOutcome struct {
	// Connector, Cloud, AccessMode identify what was being diagnosed: which
	// connector, which cloud/provider, and which access mode (e.g.
	// "read-only", "list-buckets") it attempted.
	Connector  string `json:"connector"`
	Cloud      string `json:"cloud"`
	AccessMode string `json:"access_mode"`
	// FailureClass categorizes why the access attempt failed (e.g.
	// "missing-scope", "expired-credential", "denied-policy"). Empty on a
	// resolution row — the failure was already classified on the original
	// miss row this one resolves.
	FailureClass string `json:"failure_class,omitempty"`
	// GrantCommand is the exact remediate command the operator was told to
	// run to close this gap (e.g. an `aws iam ...` or `gh auth ...`
	// invocation). Empty on a resolution row.
	GrantCommand string `json:"grant_command,omitempty"`
	// DetectedAt is when this row's diagnosis (miss or resolution) was made.
	DetectedAt time.Time `json:"detected_at"`
	// Resolved is false on a GRANT-MISS row and true on a RESOLUTION row.
	Resolved bool `json:"resolved"`
	// ResolvedRef identifies the original GRANT-MISS row this resolution
	// closes. Empty on a miss row; set on a resolution row to the commit SHA
	// that Store.Append returned when the miss row was appended — NOT a
	// synthetic/free-form key. That SHA is a genuinely resolvable identity:
	// pass it to Store.ResolveGrantMiss to read the exact original miss row
	// back (see that function's doc comment for why this works). A caller
	// closing a GRANT-MISS therefore must capture the sha Append returned for
	// the miss and carry it forward into the resolution row's ResolvedRef.
	ResolvedRef string `json:"resolved_ref,omitempty"`
}

// LoadGrantOutcomes replays the grants stream into typed GrantOutcome
// records, oldest first — mirroring LoadScans' contract exactly. A store
// that predates KindGrants, or has never had a grant diagnosis appended,
// returns an empty slice, not an error.
func (s *Store) LoadGrantOutcomes() ([]GrantOutcome, error) {
	raws, err := s.Load(KindGrants)
	if err != nil {
		return nil, err
	}
	out := make([]GrantOutcome, 0, len(raws))
	for i, raw := range raws {
		var r GrantOutcome
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("store: decode grant outcome record %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// ResolveGrantMiss looks up the original GRANT-MISS row a resolution's
// ResolvedRef points at. ref is the commit SHA Store.Append returned when the
// miss row was appended (see GrantOutcome.ResolvedRef).
//
// This works because of how commitAppend (store.go) is built: every Append
// call lands as its OWN commit whose stream blob is exactly
// prev-content + this-call's-chunk — it only ever concatenates, never
// rewrites earlier bytes. So at the EXACT commit an Append call returned, the
// last line of the grants stream blob is, byte-for-byte, the record that
// specific call appended — regardless of how many further records land on
// the stream afterward, because blobAt reads the historical tree at ref, not
// current HEAD. That makes ref a genuinely resolvable identity for the row:
// any Store handle open on the same repo can hand a resolution's ResolvedRef
// to this function and read back the exact original miss row, not merely
// round-trip an opaque string a consumer has to trust.
//
// An error is returned if ref does not name a commit in this repo, or if the
// grants stream has no record at that commit (e.g. ref points at some other
// stream's commit).
func (s *Store) ResolveGrantMiss(ref string) (GrantOutcome, error) {
	raw, err := s.blobAt(ref, KindGrants.file())
	if err != nil {
		return GrantOutcome{}, fmt.Errorf("store: resolve grant miss %s: %w", ref, err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	last := bytes.TrimSpace(lines[len(lines)-1])
	if len(last) == 0 {
		return GrantOutcome{}, fmt.Errorf("store: resolve grant miss %s: no grants record at that commit", ref)
	}
	var r GrantOutcome
	if err := json.Unmarshal(last, &r); err != nil {
		return GrantOutcome{}, fmt.Errorf("store: decode grant miss at %s: %w", ref, err)
	}
	return r, nil
}
