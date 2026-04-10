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

func emitExternalMessages(fi *finding.Finding, events []event.Event) {
	var sb strings.Builder
	for i, ev := range events {
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
