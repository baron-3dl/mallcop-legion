package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"encoding/json"
)

// makeJSONL writes events to a JSONL temp file, returns path.
func makeJSONL(t *testing.T, events []event.Event) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

var refTime = time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)

func eventsInWindow() []event.Event {
	return []event.Event{
		{ID: "e1", Source: "github", Type: "login", Actor: "user:alice",
			Timestamp: refTime.Add(-24 * time.Hour), Org: "acme", Payload: json.RawMessage(`{}`)},
		{ID: "e2", Source: "github", Type: "login", Actor: "user:bob",
			Timestamp: refTime.Add(-48 * time.Hour), Org: "acme", Payload: json.RawMessage(`{}`)},
	}
}

// TestParseDuration verifies day shorthand and standard Go durations.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"30d", 30 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"60m", 60 * time.Minute, false},
		{"bad", 0, true},
		{"xd", 0, true},
	}
	for _, tc := range tests {
		got, err := parseDuration(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("parseDuration(%q): want error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDuration(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDuration(%q): want %v, got %v", tc.in, tc.want, got)
		}
	}
}

// TestLoadEventsValid verifies JSONL parsing.
func TestLoadEventsValid(t *testing.T) {
	path := makeJSONL(t, eventsInWindow())
	events, err := loadEvents(path)
	if err != nil {
		t.Fatalf("loadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("want 2 events, got %d", len(events))
	}
}

// TestLoadEventsCorrupt verifies corrupt JSONL returns an error.
func TestLoadEventsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(path, []byte(`{"actor":"alice"}`+"\n"+`NOTJSON`+"\n"), 0644)
	_, err := loadEvents(path)
	if err == nil {
		t.Fatal("expected error on corrupt JSONL, got nil")
	}
}

// TestRunUpdate verifies the update command produces a valid baseline.
func TestRunUpdate(t *testing.T) {
	path := makeJSONL(t, eventsInWindow())
	dir := t.TempDir()
	out := filepath.Join(dir, "baseline.json")

	err := runUpdate([]string{
		"--window", "30d",
		"--events", path,
		"--out", out,
	})
	if err != nil {
		t.Fatalf("runUpdate: %v", err)
	}

	// Verify the baseline file is loadable and correct.
	eng, err := baseline.LoadEngine(out)
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	if !eng.IsKnown("user:alice") {
		t.Error("alice should be known")
	}
	if !eng.IsKnown("user:bob") {
		t.Error("bob should be known")
	}
}

// TestRunQueryKnown verifies the query command returns true for a known entity.
func TestRunQueryKnown(t *testing.T) {
	// Build baseline file directly.
	dir := t.TempDir()
	bpath := filepath.Join(dir, "baseline.json")
	eng := baseline.NewEngine()
	eng.Update(eventsInWindow(), 30*24*time.Hour, refTime)
	if err := eng.Save(bpath); err != nil {
		t.Fatal(err)
	}

	// Capture stdout via redirecting os.Stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runQuery([]string{
		"--baseline", bpath,
		"--entity", "user:alice",
		"--question", "known?",
	})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("runQuery: %v", err)
	}

	var buf strings.Builder
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	buf.Write(b[:n])
	out := strings.TrimSpace(buf.String())
	if out != "true" {
		t.Errorf("query known? for alice: want \"true\", got %q", out)
	}
}

// TestRunQueryUnknown verifies the query command returns false for an unknown entity.
func TestRunQueryUnknown(t *testing.T) {
	dir := t.TempDir()
	bpath := filepath.Join(dir, "baseline.json")
	eng := baseline.NewEngine()
	eng.Update(eventsInWindow(), 30*24*time.Hour, refTime)
	if err := eng.Save(bpath); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runQuery([]string{
		"--baseline", bpath,
		"--entity", "user:charlie",
		"--question", "known?",
	})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("runQuery: %v", err)
	}

	b := make([]byte, 1024)
	n, _ := r.Read(b)
	out := strings.TrimSpace(string(b[:n]))
	if out != "false" {
		t.Errorf("query known? for charlie: want \"false\", got %q", out)
	}
}
