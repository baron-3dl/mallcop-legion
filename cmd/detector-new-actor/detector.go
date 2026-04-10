package main

import (
	"encoding/json"
	"fmt"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// evaluate returns a Finding if the actor has not been seen in the baseline,
// or nil if the actor is known. emitted tracks actors already reported so
// only the first event per new actor produces a finding.
// This is a pure function with respect to state mutation (emitted is caller-owned).
func evaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if ev.Actor == "" {
		return nil
	}

	if bl.IsKnownActor(ev.Actor) {
		return nil
	}

	if emitted[ev.Actor] {
		return nil
	}
	emitted[ev.Actor] = true

	evidence, _ := json.Marshal(map[string]string{
		"actor":      ev.Actor,
		"source":     ev.Source,
		"event_type": ev.Type,
		"event_id":   ev.ID,
	})

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:new-actor",
		Severity:  "medium",
		Type:      "new-actor",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("actor %q not seen in baseline period (source: %s)", ev.Actor, ev.Source),
		Evidence:  evidence,
	}
}
