package resolution

import "time"

// Resolution is the actor decision applied to a finding.
// Notification binaries read this from stdin as JSON.
type Resolution struct {
	FindingID  string    `json:"finding_id"`
	Action     string    `json:"action"`     // "block", "alert", "ignore", "escalate"
	Reason     string    `json:"reason"`     // human-readable rationale
	Confidence float64   `json:"confidence"` // 0.0–1.0
	Actor      string    `json:"actor"`      // subject of the finding
	Severity   string    `json:"severity"`   // "critical", "high", "medium", "low"
	Source     string    `json:"source"`     // detector that produced the finding
	Timestamp  time.Time `json:"timestamp"`
}
