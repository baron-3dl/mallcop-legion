package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

const (
	// anomalyRatio is the multiplier over baseline that triggers a finding.
	anomalyRatio = 3.0
	// minBaselineCount is the minimum baseline count to be meaningful.
	// Groups with fewer baseline events are skipped to avoid false positives
	// on rarely-seen event types.
	minBaselineCount = 5
)

type groupKey struct {
	source    string
	eventType string
}

// evaluateAll counts events per (source, event_type) group and returns
// findings for groups that exceed anomalyRatio × baseline count.
// Results are ordered deterministically by source then event_type.
// This is a pure function: no I/O, no globals mutated.
func evaluateAll(events []event.Event, bl *baseline.Baseline) []finding.Finding {
	// Count current events per group; track first event ID per group for finding ID.
	counts := make(map[groupKey]int)
	firstID := make(map[groupKey]string)
	firstTS := make(map[groupKey]interface{})
	_ = firstTS

	type groupMeta struct {
		firstEventID string
		firstEvent   event.Event
	}
	meta := make(map[groupKey]groupMeta)

	for _, ev := range events {
		k := groupKey{ev.Source, ev.Type}
		counts[k]++
		if _, seen := meta[k]; !seen {
			meta[k] = groupMeta{firstEventID: ev.ID, firstEvent: ev}
		}
		_ = firstID
	}

	// Sort groups for deterministic output.
	keys := make([]groupKey, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].eventType < keys[j].eventType
	})

	var findings []finding.Finding
	for _, k := range keys {
		currentCount := counts[k]
		baselineCount := bl.FreqCount(k.source, k.eventType)

		if baselineCount < minBaselineCount {
			continue
		}

		if float64(currentCount) <= anomalyRatio*float64(baselineCount) {
			continue
		}

		m := meta[k]
		ratio := float64(currentCount) / float64(baselineCount)

		evidence, _ := json.Marshal(map[string]interface{}{
			"source":         k.source,
			"event_type":     k.eventType,
			"current_count":  currentCount,
			"baseline_count": baselineCount,
			"ratio":          fmt.Sprintf("%.1f", ratio),
		})

		findings = append(findings, finding.Finding{
			ID:        "finding-" + m.firstEventID,
			Source:    "detector:volume-anomaly",
			Severity:  "medium",
			Type:      "volume-anomaly",
			Actor:     m.firstEvent.Actor,
			Timestamp: m.firstEvent.Timestamp,
			Reason: fmt.Sprintf(
				"%s:%s volume spike: %d events vs baseline %d (%.1f×)",
				k.source, k.eventType, currentCount, baselineCount, ratio,
			),
			Evidence: evidence,
		})
	}

	return findings
}
