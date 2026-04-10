package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// Rate anomaly multiplier thresholds.
const (
	// highRateMultiplier: event request_count is this many times baseline → high severity.
	highRateMultiplier = 20
	// mediumRateMultiplier → medium severity.
	mediumRateMultiplier = 5
	// absoluteHighBurst: request_count in a single event above this triggers high regardless.
	absoluteHighBurst = 1000
	// absoluteMediumBurst triggers medium regardless of baseline.
	absoluteMediumBurst = 200
)

// sensitiveEndpoints are API endpoints that are unusual to access at high rates.
var sensitiveEndpoints = []string{
	"/admin/",
	"/internal/",
	"/debug/",
	"/metrics/",
	"/actuator/",
	"/_cluster/",
	"/_cat/",
	"/v1/keys",
	"/v1/tokens",
	"/v1/credentials",
	"/v1/secrets",
	"/api/v1/namespaces",
	"/api/v1/secrets",
}

// ratePayload is the expected payload structure for API rate events.
type ratePayload struct {
	RequestCount int    `json:"request_count"`
	Endpoint     string `json:"endpoint"`
	StatusCode   int    `json:"status_code"`
	WindowSecs   int    `json:"window_secs"`
}

// evaluate returns a Finding if the event shows rate anomaly patterns.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	if ev.Type != "api_request" && ev.Type != "api_burst" && ev.Type != "rate_event" {
		return nil
	}

	var rp ratePayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &rp)
	}

	count := rp.RequestCount
	if count <= 0 {
		count = 1
	}

	// Rule 1: absolute burst thresholds (no baseline needed).
	if count >= absoluteHighBurst {
		isSensitive := isSensitiveEndpoint(rp.Endpoint)
		severity := "high"
		reason := fmt.Sprintf("request burst by %q: %d requests", ev.Actor, count)
		if isSensitive {
			severity = "high"
			reason = fmt.Sprintf("request burst to sensitive endpoint %q by %q: %d requests", rp.Endpoint, ev.Actor, count)
		}
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":         ev.Actor,
			"request_count": count,
			"endpoint":      rp.Endpoint,
			"rule":          "absolute-burst",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:rate-anomaly",
			Severity:  severity,
			Type:      "rate-anomaly",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    reason,
			Evidence:  evidence,
		}
	}

	if count >= absoluteMediumBurst {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":         ev.Actor,
			"request_count": count,
			"endpoint":      rp.Endpoint,
			"rule":          "absolute-burst",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:rate-anomaly",
			Severity:  "medium",
			Type:      "rate-anomaly",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("elevated request rate by %q: %d requests", ev.Actor, count),
			Evidence:  evidence,
		}
	}

	// Rule 2: frequency anomaly vs baseline.
	baselineCount := bl.FreqCount(ev.Source, ev.Type)
	if baselineCount > 0 {
		ratio := float64(count) / float64(baselineCount)
		if ratio >= float64(highRateMultiplier) {
			evidence, _ := json.Marshal(map[string]interface{}{
				"actor":           ev.Actor,
				"request_count":   count,
				"baseline_count":  baselineCount,
				"ratio":           fmt.Sprintf("%.1f", ratio),
				"endpoint":        rp.Endpoint,
				"rule":            "rate-frequency-anomaly",
			})
			return &finding.Finding{
				ID:        "finding-" + ev.ID,
				Source:    "detector:rate-anomaly",
				Severity:  "high",
				Type:      "rate-anomaly",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("rate anomaly for %q: %.0fx baseline (%s:%s)", ev.Actor, ratio, ev.Source, ev.Type),
				Evidence:  evidence,
			}
		}
		if ratio >= float64(mediumRateMultiplier) {
			evidence, _ := json.Marshal(map[string]interface{}{
				"actor":           ev.Actor,
				"request_count":   count,
				"baseline_count":  baselineCount,
				"ratio":           fmt.Sprintf("%.1f", ratio),
				"endpoint":        rp.Endpoint,
				"rule":            "rate-frequency-anomaly",
			})
			return &finding.Finding{
				ID:        "finding-" + ev.ID,
				Source:    "detector:rate-anomaly",
				Severity:  "medium",
				Type:      "rate-anomaly",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("elevated rate for %q: %.0fx baseline (%s:%s)", ev.Actor, ratio, ev.Source, ev.Type),
				Evidence:  evidence,
			}
		}
	}

	// Rule 3: sensitive endpoint access at any elevated rate (even below absolute burst).
	if isSensitiveEndpoint(rp.Endpoint) && count > 10 {
		evidence, _ := json.Marshal(map[string]interface{}{
			"actor":         ev.Actor,
			"request_count": count,
			"endpoint":      rp.Endpoint,
			"rule":          "sensitive-endpoint-rate",
		})
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:rate-anomaly",
			Severity:  "medium",
			Type:      "rate-anomaly",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("repeated access to sensitive endpoint %q by %q: %d requests", rp.Endpoint, ev.Actor, count),
			Evidence:  evidence,
		}
	}

	return nil
}

// isSensitiveEndpoint returns true when the endpoint path matches a known
// sensitive API path prefix.
func isSensitiveEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	lower := strings.ToLower(endpoint)
	for _, prefix := range sensitiveEndpoints {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}
