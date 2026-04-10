package event

import (
	"encoding/json"
	"time"
)

// Event is a normalized security event from a mallcop connector.
type Event struct {
	ID        string          `json:"id"`
	Source    string          `json:"source"`
	Type      string          `json:"type"`
	Actor     string          `json:"actor"`
	Timestamp time.Time       `json:"timestamp"`
	Org       string          `json:"org"`
	Payload   json.RawMessage `json:"payload"`
}
