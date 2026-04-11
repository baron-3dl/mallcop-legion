package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

const (
	markerBegin = "[USER_DATA_BEGIN]"
	markerEnd   = "[USER_DATA_END]"
)

// sanitize wraps external data in injection-defense markers.
// Any literal marker within the data is escaped to prevent early termination.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "[USER_DATA_BEGIN]", `[\[USER_DATA_BEGIN\]]`)
	s = strings.ReplaceAll(s, "[USER_DATA_END]", `[\[USER_DATA_END\]]`)
	return markerBegin + "\n" + s + "\n" + markerEnd
}

// sanitizeInline wraps a single-line value without surrounding newlines,
// escaping markers inside.
func sanitizeInline(s string) string {
	s = strings.ReplaceAll(s, "[USER_DATA_BEGIN]", `[\[USER_DATA_BEGIN\]]`)
	s = strings.ReplaceAll(s, "[USER_DATA_END]", `[\[USER_DATA_END\]]`)
	return markerBegin + s + markerEnd
}

func loadFinding(path string) (*finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var fi finding.Finding
	if err := json.NewDecoder(f).Decode(&fi); err != nil {
		return nil, err
	}
	return &fi, nil
}

// loadEvents reads events from path, supporting both JSON array and JSONL formats.
// JSON array: starts with '['. JSONL: one JSON object per line.
func loadEvents(path string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	if delim, ok := tok.(json.Delim); ok && delim == '[' {
		// JSON array: decode elements until ']'
		var events []event.Event
		for dec.More() {
			var ev event.Event
			if err := dec.Decode(&ev); err != nil {
				return nil, err
			}
			events = append(events, ev)
		}
		return events, nil
	}

	// JSONL: first token was start of an object '{'. Re-open and scan line by line.
	f2, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f2.Close()
	var events []event.Event
	dec2 := json.NewDecoder(f2)
	for dec2.More() {
		var ev event.Event
		if err := dec2.Decode(&ev); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

// relevantEvents picks the subset of events that relate to the finding.
//
// Selection order (first match wins):
//  1. Event IDs referenced by the finding's evidence:
//       {"event_id": "..."}       (single, as emitted by the V3 detectors)
//       {"event_ids": ["...", ...]} (plural, for multi-event findings)
//  2. Events matching the finding's actor (fi.Actor), when the actor is
//     non-empty. This is the fallback for detectors that don't pin specific
//     events — it still narrows from "everything pulled this scan" to
//     "everything this actor did this scan" (usually 10–100x reduction).
//  3. If neither rule matches and the finding is otherwise related to the
//     events (empty actor, no evidence), emit nothing. The triage agent
//     will see an empty [USER_DATA_*] block and can escalate for missing
//     context rather than being drowned in unrelated events.
//
// The previous implementation dumped every event blindly, which cost tokens
// and degraded triage quality. Surfaced during the v2-deploy dogfood scan
// on 2026-04-11: 648 events pulled → 13k-token prompt for a single-actor
// finding. rd: mallcoppro-014.
func relevantEvents(fi *finding.Finding, events []event.Event) []event.Event {
	// Rule 1: explicit event_id(s) from evidence.
	if idSet := extractEvidenceEventIDs(fi.Evidence); len(idSet) > 0 {
		out := make([]event.Event, 0, len(idSet))
		for _, ev := range events {
			if _, ok := idSet[ev.ID]; ok {
				out = append(out, ev)
			}
		}
		return out
	}

	// Rule 2: actor match.
	if fi.Actor != "" {
		out := make([]event.Event, 0)
		for _, ev := range events {
			if ev.Actor == fi.Actor {
				out = append(out, ev)
			}
		}
		return out
	}

	// Rule 3: no selection criteria — emit nothing. Let the triage agent
	// decide what to do with a finding that has no anchoring context.
	return nil
}

// extractEvidenceEventIDs pulls event_id / event_ids values out of a
// finding's Evidence blob. The evidence shape is detector-defined, but by
// convention the keys are "event_id" (string) and "event_ids" (array of
// strings). Returns nil when no IDs are present.
func extractEvidenceEventIDs(evidence json.RawMessage) map[string]struct{} {
	if len(evidence) == 0 {
		return nil
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(evidence, &parsed); err != nil {
		return nil
	}

	ids := make(map[string]struct{})
	if raw, ok := parsed["event_id"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			ids[s] = struct{}{}
		}
	}
	if raw, ok := parsed["event_ids"]; ok {
		var xs []string
		if err := json.Unmarshal(raw, &xs); err == nil {
			for _, s := range xs {
				if s != "" {
					ids[s] = struct{}{}
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

func emitExternalMessages(fi *finding.Finding, events []event.Event) {
	selected := relevantEvents(fi, events)
	var sb strings.Builder
	for i, ev := range selected {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("event_id: %s\n", ev.ID))
		sb.WriteString(fmt.Sprintf("source: %s\n", ev.Source))
		sb.WriteString(fmt.Sprintf("type: %s\n", ev.Type))
		sb.WriteString(fmt.Sprintf("timestamp: %s\n", ev.Timestamp.Format("2006-01-02T15:04:05Z07:00")))
		if len(ev.Payload) > 0 {
			sb.WriteString(fmt.Sprintf("payload: %s", string(ev.Payload)))
		}
	}
	fmt.Printf("# external-messages\n%s\n", sanitize(sb.String()))
}

func emitStandingFacts(fi *finding.Finding, bl *baseline.Baseline) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("baseline_users: %d known users\n", len(bl.KnownUsers)))
	// Find last scan from most recent LastSeen across profiles
	var lastScan string
	for _, profile := range bl.KnownUsers {
		ts := profile.LastSeen.Format("2006-01-02T15:04:05Z07:00")
		if ts > lastScan {
			lastScan = ts
		}
	}
	if lastScan != "" {
		sb.WriteString(fmt.Sprintf("last_scan: %s", lastScan))
	} else {
		sb.WriteString("last_scan: unknown")
	}
	// Baseline data is operator-configured — NOT wrapped
	fmt.Printf("# standing-facts\n%s\n", sb.String())
}

func emitSpec(fi *finding.Finding) {
	// All finding fields are wrapped — fi.ID, fi.Source, fi.Type, fi.Severity
	// may originate from semi-trusted input and are injection vectors if left bare.
	fmt.Printf("# spec\n")
	fmt.Printf("Finding: %s (%s, %s)\n", sanitizeInline(fi.ID), sanitizeInline(fi.Type), sanitizeInline(fi.Severity))
	fmt.Printf("Source: %s\n", sanitizeInline(fi.Source))
	fmt.Printf("Actor: %s\n", sanitizeInline(fi.Actor))
	if fi.Reason != "" {
		fmt.Printf("Reason: %s\n", sanitizeInline(fi.Reason))
	}
	if len(fi.Evidence) > 0 {
		fmt.Printf("Evidence: %s\n", sanitize(string(fi.Evidence)))
	}
}

func main() {
	findingPath := flag.String("finding", "", "path to finding JSON file")
	eventsPath := flag.String("events", "", "path to events JSON or JSONL file")
	baselinePath := flag.String("baseline", "", "path to baseline JSON file")
	field := flag.String("field", "", "field to emit: external-messages | standing-facts | spec")
	flag.Parse()

	if *findingPath == "" || *eventsPath == "" || *baselinePath == "" || *field == "" {
		fmt.Fprintln(os.Stderr, "usage: mallcop-finding-context --finding <path> --events <path> --baseline <path> --field <field>")
		fmt.Fprintln(os.Stderr, "fields: external-messages, standing-facts, spec")
		os.Exit(1)
	}

	fi, err := loadFinding(*findingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading finding: %v\n", err)
		os.Exit(1)
	}

	events, err := loadEvents(*eventsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading events: %v\n", err)
		os.Exit(1)
	}

	bl, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading baseline: %v\n", err)
		os.Exit(1)
	}

	switch *field {
	case "external-messages":
		emitExternalMessages(fi, events)
	case "standing-facts":
		emitStandingFacts(fi, bl)
	case "spec":
		emitSpec(fi)
	default:
		fmt.Fprintf(os.Stderr, "unknown field %q: must be external-messages, standing-facts, or spec\n", *field)
		os.Exit(1)
	}
}
