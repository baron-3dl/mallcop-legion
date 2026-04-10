package main

import (
	"encoding/json"
	"fmt"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// evaluate returns a Finding if the event's UTC hour is outside the actor's
// known active hours in the baseline. Returns nil when:
//   - no actor-hours baseline data exists (nothing to compare against)
//   - the actor has no hour profile (unknown actor, handled by new-actor)
//   - the event hour is within the actor's known hours
//
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	// Without baseline timing data, every event looks "unusual" — skip.
	if !bl.HasActorHours() {
		return nil
	}

	// If this actor has no timing profile, skip — new-actor handles unknowns.
	if _, ok := bl.ActorHours[ev.Actor]; !ok {
		return nil
	}

	hour := ev.Timestamp.UTC().Hour()
	if bl.KnownHour(ev.Actor, hour) {
		return nil
	}

	evidence, _ := json.Marshal(map[string]interface{}{
		"actor":      ev.Actor,
		"hour_utc":   hour,
		"source":     ev.Source,
		"event_type": ev.Type,
		"event_id":   ev.ID,
	})

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:unusual-timing",
		Severity:  "low",
		Type:      "unusual-timing",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("actor %q active at unusual hour %02d:xx UTC (not in baseline pattern)", ev.Actor, hour),
		Evidence:  evidence,
	}
}
