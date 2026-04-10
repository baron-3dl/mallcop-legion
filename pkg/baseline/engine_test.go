package baseline_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
)

// makeEvent constructs a test event with the given actor and timestamp.
func makeEvent(id, actor string, ts time.Time) event.Event {
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      "login",
		Actor:     actor,
		Timestamp: ts,
		Org:       "acme",
		Payload:   json.RawMessage(`{}`),
	}
}

var t0 = time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)

// TestEntityLearning verifies actors within the window appear as known.
func TestEntityLearning(t *testing.T) {
	events := []event.Event{
		makeEvent("e1", "user:alice", t0),
		makeEvent("e2", "user:bob", t0.Add(-24*time.Hour)),
	}
	eng := baseline.NewEngine()
	eng.Update(events, 30*24*time.Hour, t0)

	if !eng.IsKnown("user:alice") {
		t.Error("alice should be known after appearing in events")
	}
	if !eng.IsKnown("user:bob") {
		t.Error("bob should be known after appearing in events")
	}
	if eng.IsKnown("user:charlie") {
		t.Error("charlie should not be known — never seen in events")
	}
}

// TestSlidingWindowEviction verifies events outside the window are excluded.
func TestSlidingWindowEviction(t *testing.T) {
	old := t0.Add(-31 * 24 * time.Hour) // 31 days ago — outside 30d window
	events := []event.Event{
		makeEvent("e1", "user:alice", t0),
		makeEvent("e2", "user:oldguy", old),
	}
	eng := baseline.NewEngine()
	eng.Update(events, 30*24*time.Hour, t0)

	if !eng.IsKnown("user:alice") {
		t.Error("alice (in window) should be known")
	}
	if eng.IsKnown("user:oldguy") {
		t.Error("oldguy (outside window) should be evicted")
	}
}

// TestFrequencyTable verifies event counts are tracked per entity.
func TestFrequencyTable(t *testing.T) {
	events := []event.Event{
		makeEvent("e1", "user:alice", t0),
		makeEvent("e2", "user:alice", t0.Add(-1*time.Hour)),
		makeEvent("e3", "user:alice", t0.Add(-2*time.Hour)),
		makeEvent("e4", "user:bob", t0),
	}
	eng := baseline.NewEngine()
	eng.Update(events, 30*24*time.Hour, t0)

	if got := eng.EventCount("user:alice"); got != 3 {
		t.Errorf("alice event count: want 3, got %d", got)
	}
	if got := eng.EventCount("user:bob"); got != 1 {
		t.Errorf("bob event count: want 1, got %d", got)
	}
	if got := eng.EventCount("user:unknown"); got != 0 {
		t.Errorf("unknown event count: want 0, got %d", got)
	}
}

// TestSaveLoadRoundtrip verifies the engine serializes and deserializes correctly.
func TestSaveLoadRoundtrip(t *testing.T) {
	events := []event.Event{
		makeEvent("e1", "user:alice", t0),
		makeEvent("e2", "user:bob", t0.Add(-1*time.Hour)),
	}
	eng := baseline.NewEngine()
	eng.Update(events, 30*24*time.Hour, t0)

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := eng.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := baseline.LoadEngine(path)
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	if !loaded.IsKnown("user:alice") {
		t.Error("alice should be known after load")
	}
	if !loaded.IsKnown("user:bob") {
		t.Error("bob should be known after load")
	}
	if loaded.IsKnown("user:charlie") {
		t.Error("charlie should not be known after load")
	}
}

// TestDeterministicOutput verifies same events produce identical JSON bytes.
func TestDeterministicOutput(t *testing.T) {
	events := []event.Event{
		makeEvent("e1", "user:alice", t0),
		makeEvent("e2", "user:bob", t0.Add(-1*time.Hour)),
		makeEvent("e3", "user:carol", t0.Add(-2*time.Hour)),
	}

	dir := t.TempDir()
	path1 := filepath.Join(dir, "b1.json")
	path2 := filepath.Join(dir, "b2.json")

	eng1 := baseline.NewEngine()
	eng1.Update(events, 30*24*time.Hour, t0)
	if err := eng1.Save(path1); err != nil {
		t.Fatal(err)
	}

	eng2 := baseline.NewEngine()
	eng2.Update(events, 30*24*time.Hour, t0)
	if err := eng2.Save(path2); err != nil {
		t.Fatal(err)
	}

	b1, _ := os.ReadFile(path1)
	b2, _ := os.ReadFile(path2)
	if string(b1) != string(b2) {
		t.Errorf("non-deterministic output:\nrun1: %s\nrun2: %s", b1, b2)
	}
}

// TestCorruptedBaselineRejectsLoad verifies corrupted files fail loudly.
func TestCorruptedBaselineRejectsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"entities":INVALID`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := baseline.LoadEngine(path)
	if err == nil {
		t.Fatal("LoadEngine on corrupt file should return an error, got nil")
	}
}

// TestSchemaMismatchFails verifies version mismatch is rejected.
func TestSchemaMismatchFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.json")
	// Write a file with a future/wrong schema version.
	raw := `{"version":9999,"generated_at":"2026-04-10T12:00:00Z","window_seconds":2592000,"entities":{}}`
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := baseline.LoadEngine(path)
	if err == nil {
		t.Fatal("LoadEngine with wrong schema version should return an error")
	}
}

// TestEmptyEventsProducesEmptyBaseline ensures no entity is learned from an empty list.
func TestEmptyEventsProducesEmptyBaseline(t *testing.T) {
	eng := baseline.NewEngine()
	eng.Update(nil, 30*24*time.Hour, t0)
	if eng.IsKnown("user:alice") {
		t.Error("no entity should be known in empty baseline")
	}
}
