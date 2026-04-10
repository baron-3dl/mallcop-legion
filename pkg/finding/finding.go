package finding

import (
	"encoding/json"
	"time"
)

// Finding is a security finding emitted by a detector.
type Finding struct {
	ID        string          `json:"id"`
	Source    string          `json:"source"`    // "detector:unusual-login"
	Severity  string          `json:"severity"`  // "critical", "high", "medium", "low"
	Type      string          `json:"type"`      // "unusual-login"
	Actor     string          `json:"actor"`     // GitHub username
	Timestamp time.Time       `json:"timestamp"`
	Reason    string          `json:"reason"`    // human-readable explanation
	Evidence  json.RawMessage `json:"evidence"`  // supporting data
}
