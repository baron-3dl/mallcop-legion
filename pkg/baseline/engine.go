package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/event"
)

// SchemaVersion is incremented on any breaking change to the baseline JSON format.
const SchemaVersion = 1

// engineJSON is the on-disk representation.
type engineJSON struct {
	Version       int                      `json:"version"`
	GeneratedAt   time.Time                `json:"generated_at"`
	WindowSeconds int64                    `json:"window_seconds"`
	Entities      map[string]*entityRecord `json:"entities"`
}

// entityRecord holds per-entity statistics.
type entityRecord struct {
	// EventCount is the number of events observed for this entity within the window.
	EventCount int `json:"event_count"`
}

// Engine maintains learned frequency tables and known-entity sets.
// Use NewEngine() to create, Update() to populate, and Save()/LoadEngine() for persistence.
type Engine struct {
	generatedAt   time.Time
	windowSeconds int64
	entities      map[string]*entityRecord // entity key → stats
}

// NewEngine returns a zero-value baseline engine ready for Update.
func NewEngine() *Engine {
	return &Engine{
		entities: make(map[string]*entityRecord),
	}
}

// Update rebuilds the engine state from the provided events using the given sliding window.
// now is the reference timestamp for window boundary calculation (use time.Now() in production).
// Calling Update again replaces all prior state.
func (e *Engine) Update(events []event.Event, window time.Duration, now time.Time) {
	cutoff := now.Add(-window)
	e.generatedAt = now
	e.windowSeconds = int64(window.Seconds())
	e.entities = make(map[string]*entityRecord)

	for _, ev := range events {
		if ev.Timestamp.Before(cutoff) {
			continue // outside sliding window — evict
		}
		actor := ev.Actor
		if actor == "" {
			continue
		}
		rec, ok := e.entities[actor]
		if !ok {
			rec = &entityRecord{}
			e.entities[actor] = rec
		}
		rec.EventCount++
	}
}

// IsKnown returns true if the entity was observed within the baseline window.
func (e *Engine) IsKnown(entity string) bool {
	_, ok := e.entities[entity]
	return ok
}

// EventCount returns the number of events seen for the entity within the window.
// Returns 0 for unknown entities.
func (e *Engine) EventCount(entity string) int {
	rec, ok := e.entities[entity]
	if !ok {
		return 0
	}
	return rec.EventCount
}

// Save writes the baseline to disk as deterministic JSON.
// Same engine state always produces identical bytes (sorted keys, stable encoding).
func (e *Engine) Save(path string) error {
	data := engineJSON{
		Version:       SchemaVersion,
		GeneratedAt:   e.generatedAt.UTC(),
		WindowSeconds: e.windowSeconds,
		Entities:      e.entities,
	}

	// Marshal to canonical JSON with sorted keys.
	// json.Marshal sorts struct fields but map keys are sorted by Go 1.12+.
	// We use a custom encoder to ensure sorted map keys and consistent formatting.
	b, err := marshalCanonical(data)
	if err != nil {
		return fmt.Errorf("baseline save marshal: %w", err)
	}
	return os.WriteFile(path, b, 0644)
}

// LoadEngine reads a baseline file from disk.
// Returns an error if the file is corrupt, unreadable, or has a schema version mismatch.
// A schema mismatch or corrupt file MUST fail loudly — never return an empty engine silently.
func LoadEngine(path string) (*Engine, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline load read: %w", err)
	}

	var data engineJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("baseline load parse: %w", err)
	}

	if data.Version != SchemaVersion {
		return nil, fmt.Errorf("baseline schema version mismatch: file has v%d, engine supports v%d",
			data.Version, SchemaVersion)
	}

	entities := data.Entities
	if entities == nil {
		entities = make(map[string]*entityRecord)
	}

	return &Engine{
		generatedAt:   data.GeneratedAt,
		windowSeconds: data.WindowSeconds,
		entities:      entities,
	}, nil
}

// marshalCanonical produces deterministic JSON by sorting map keys explicitly.
// We re-encode with sorted entity keys to guarantee byte-for-byte reproducibility.
func marshalCanonical(data engineJSON) ([]byte, error) {
	// Build a sorted slice of entity keys.
	keys := make([]string, 0, len(data.Entities))
	for k := range data.Entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Manually construct JSON to guarantee key ordering for the top-level map.
	var buf bytes.Buffer
	buf.WriteString(`{"version":`)
	vb, _ := json.Marshal(data.Version)
	buf.Write(vb)

	buf.WriteString(`,"generated_at":`)
	tsb, err := json.Marshal(data.GeneratedAt)
	if err != nil {
		return nil, err
	}
	buf.Write(tsb)

	buf.WriteString(`,"window_seconds":`)
	wsb, _ := json.Marshal(data.WindowSeconds)
	buf.Write(wsb)

	buf.WriteString(`,"entities":{`)
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		rb, err := json.Marshal(data.Entities[k])
		if err != nil {
			return nil, err
		}
		buf.Write(rb)
	}
	buf.WriteString(`}}`)

	// Append newline for POSIX compliance.
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
