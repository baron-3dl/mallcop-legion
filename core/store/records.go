package store

import (
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
