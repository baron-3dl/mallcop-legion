package main

import (
	"encoding/json"
	"fmt"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// exfilEventTypes are event types that carry data-transfer signals.
var exfilEventTypes = map[string]bool{
	"download":       true,
	"bulk_export":    true,
	"data_export":    true,
	"file_download":  true,
	"repo_clone":     true,
	"repo_archive":   true,
	"object_get":     true,
	"list_objects":   true,
	"bulk_read":      true,
	"api_export":     true,
}

// thresholds for anomaly detection.
const (
	// highVolumeThresholdMB is the per-event volume that triggers a high-severity finding.
	highVolumeThresholdMB = 500
	// mediumVolumeThresholdMB triggers medium severity.
	mediumVolumeThresholdMB = 100
	// highResourceCountThreshold triggers a high finding when a single event touches many resources.
	highResourceCountThreshold = 100
	// mediumResourceCountThreshold triggers medium.
	mediumResourceCountThreshold = 20
	// freqMultiplierHigh: event count is this many times the baseline → high.
	freqMultiplierHigh = 10
	// freqMultiplierMedium: event count is this many times the baseline → medium.
	freqMultiplierMedium = 3
)

// exfilPayload is the expected payload structure for data-transfer events.
type exfilPayload struct {
	BytesTransferred int64    `json:"bytes_transferred"`
	FilesAccessed    int      `json:"files_accessed"`
	ResourceCount    int      `json:"resource_count"`
	Destination      string   `json:"destination"`
	Resources        []string `json:"resources"`
}

// evaluate returns a Finding if the event shows exfiltration patterns.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	if !exfilEventTypes[ev.Type] {
		return nil
	}

	var ep exfilPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &ep)
	}

	// Normalise resource count (take the max of the two payload fields).
	resourceCount := ep.ResourceCount
	if len(ep.Resources) > resourceCount {
		resourceCount = len(ep.Resources)
	}
	if ep.FilesAccessed > resourceCount {
		resourceCount = ep.FilesAccessed
	}

	volumeMB := ep.BytesTransferred / (1024 * 1024)

	// Rule 1: absolute volume thresholds.
	if volumeMB >= highVolumeThresholdMB {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":             ev.Actor,
			"event_type":        ev.Type,
			"bytes_transferred": ep.BytesTransferred,
			"volume_mb":         volumeMB,
			"destination":       ep.Destination,
			"rule":              "high-volume-transfer",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:exfil-pattern",
			Severity:  "high",
			Type:      "exfil-pattern",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("large data transfer by %q: %d MB in single event", ev.Actor, volumeMB),
			Evidence:  evidence,
		}
	}

	if volumeMB >= mediumVolumeThresholdMB {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":             ev.Actor,
			"event_type":        ev.Type,
			"bytes_transferred": ep.BytesTransferred,
			"volume_mb":         volumeMB,
			"destination":       ep.Destination,
			"rule":              "anomalous-volume-transfer",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:exfil-pattern",
			Severity:  "medium",
			Type:      "exfil-pattern",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("elevated data transfer by %q: %d MB in single event", ev.Actor, volumeMB),
			Evidence:  evidence,
		}
	}

	// Rule 2: bulk resource access.
	if resourceCount >= highResourceCountThreshold {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":          ev.Actor,
			"event_type":     ev.Type,
			"resource_count": resourceCount,
			"rule":           "bulk-resource-access",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:exfil-pattern",
			Severity:  "high",
			Type:      "exfil-pattern",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("bulk resource access by %q: %d resources in single event", ev.Actor, resourceCount),
			Evidence:  evidence,
		}
	}

	if resourceCount >= mediumResourceCountThreshold {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":          ev.Actor,
			"event_type":     ev.Type,
			"resource_count": resourceCount,
			"rule":           "bulk-resource-access",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:exfil-pattern",
			Severity:  "medium",
			Type:      "exfil-pattern",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("anomalous resource access by %q: %d resources in single event", ev.Actor, resourceCount),
			Evidence:  evidence,
		}
	}

	// Rule 3: frequency anomaly vs baseline.
	baselineCount := bl.FreqCount(ev.Source, ev.Type)
	if baselineCount > 0 {
		// Use resource count as a proxy for "event magnitude" when present,
		// otherwise treat the event as count=1.
		magnitude := 1
		if resourceCount > 0 {
			magnitude = resourceCount
		}
		ratio := float64(magnitude) / float64(baselineCount)
		if ratio >= float64(freqMultiplierHigh) {
			evidence, _ := json.Marshal(map[string]interface{}{
				"actor":           ev.Actor,
				"event_type":      ev.Type,
				"source":          ev.Source,
				"baseline_count":  baselineCount,
				"event_magnitude": magnitude,
				"ratio":           fmt.Sprintf("%.1f", ratio),
				"rule":            "frequency-anomaly",
			})
			return &finding.Finding{
				ID:        "finding-" + ev.ID,
				Source:    "detector:exfil-pattern",
				Severity:  "high",
				Type:      "exfil-pattern",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("exfil frequency anomaly for %q: %.0fx baseline (%s:%s)", ev.Actor, ratio, ev.Source, ev.Type),
				Evidence:  evidence,
			}
		}
		if ratio >= float64(freqMultiplierMedium) {
			evidence, _ := json.Marshal(map[string]interface{}{
				"actor":           ev.Actor,
				"event_type":      ev.Type,
				"source":          ev.Source,
				"baseline_count":  baselineCount,
				"event_magnitude": magnitude,
				"ratio":           fmt.Sprintf("%.1f", ratio),
				"rule":            "frequency-anomaly",
			})
			return &finding.Finding{
				ID:        "finding-" + ev.ID,
				Source:    "detector:exfil-pattern",
				Severity:  "medium",
				Type:      "exfil-pattern",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("elevated exfil frequency for %q: %.0fx baseline (%s:%s)", ev.Actor, ratio, ev.Source, ev.Type),
				Evidence:  evidence,
			}
		}
	}

	return nil
}
