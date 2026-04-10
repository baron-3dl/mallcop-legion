package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// elevationEventTypes are event types that may carry privilege escalation.
var elevationEventTypes = map[string]bool{
	"role_assignment":   true,
	"collaborator_added": true,
	"permission_change": true,
	"admin_action":      true,
	"member_added":      true,
}

// elevatedKeywords are role/permission values that indicate elevated access.
var elevatedKeywords = map[string]bool{
	"admin":       true,
	"owner":       true,
	"write":       true,
	"contributor": true,
	"maintainer":  true,
}

// privPayload is the expected payload structure for privilege escalation events.
type privPayload struct {
	RoleName        string `json:"role_name"`
	PermissionLevel string `json:"permission_level"`
	TargetUser      string `json:"target_user"`
}

// isElevated returns true when the event indicates privilege elevation.
// admin_action is always elevated; other types check payload fields.
func isElevated(ev event.Event, pp privPayload) bool {
	if ev.Type == "admin_action" {
		return true
	}
	for _, val := range []string{pp.RoleName, pp.PermissionLevel} {
		if elevatedKeywords[strings.ToLower(val)] {
			return true
		}
	}
	return false
}

// roleKey derives a stable role identifier from the payload.
func roleKey(ev event.Event, pp privPayload) string {
	if pp.RoleName != "" {
		return strings.ToLower(pp.RoleName)
	}
	if pp.PermissionLevel != "" {
		return strings.ToLower(pp.PermissionLevel)
	}
	return ev.Type
}

// evaluate returns a Finding if the event represents a new privilege escalation
// not already in the baseline. emitted tracks (actor:role) pairs already reported.
// This is a pure function with respect to state mutation (emitted is caller-owned).
func evaluate(ev event.Event, bl *baseline.Baseline, emitted map[string]bool) *finding.Finding {
	if !elevationEventTypes[ev.Type] {
		return nil
	}

	var pp privPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &pp)
	}

	if !isElevated(ev, pp) {
		return nil
	}

	rk := roleKey(ev, pp)

	if bl.IsKnownRole(ev.Actor, rk) {
		return nil
	}

	dedupKey := ev.Actor + ":" + rk
	if emitted[dedupKey] {
		return nil
	}
	emitted[dedupKey] = true

	severity := "high"
	if ev.Type == "admin_action" || rk == "admin" || rk == "owner" {
		severity = "critical"
	}

	evidence, _ := json.Marshal(map[string]string{
		"actor":            ev.Actor,
		"role":             rk,
		"event_type":       ev.Type,
		"target_user":      pp.TargetUser,
		"permission_level": pp.PermissionLevel,
		"event_id":         ev.ID,
	})

	reason := fmt.Sprintf("privilege escalation: %q granted %q role on %s", ev.Actor, rk, ev.Source)
	if pp.TargetUser != "" {
		reason = fmt.Sprintf("privilege escalation: %q granted %q to %q on %s", ev.Actor, rk, pp.TargetUser, ev.Source)
	}

	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:priv-escalation",
		Severity:  severity,
		Type:      "priv-escalation",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    reason,
		Evidence:  evidence,
	}
}
