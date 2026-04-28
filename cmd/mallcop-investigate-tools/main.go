// Package main implements mallcop-investigate-tools — a single read-only binary
// used by the investigate (and triage) dispositions to query fixture data
// without network egress or shell escapes.
//
// # Security invariants
//
// The following are enforced structurally (no imports allowed) AND checked by
// TestInvestigateTools_NoNetworkImports:
//
//   - No network egress: "net/http" and "net" are forbidden imports.
//   - No shell escapes: "os/exec" is a forbidden import.
//   - No symlink escape: every fixture path is resolved with filepath.EvalSymlinks
//     and checked to remain inside the declared fixture dir.
//   - Read-only: no os.WriteFile, os.Create, or equivalent calls.
//
// Usage:
//
//	mallcop-investigate-tools --tool check-baseline \
//	  --mode exam --fixture-dir /path/to/fixture \
//	  --entity alice@example.com --source github --hours 168
//
//	mallcop-investigate-tools --tool search-events \
//	  --mode exam --fixture-dir /path/to/fixture \
//	  --actor alice@example.com --source github \
//	  --since 2026-04-01T00:00:00Z --until 2026-04-11T00:00:00Z
//
//	mallcop-investigate-tools --tool search-findings \
//	  --mode exam --fixture-dir /path/to/fixture \
//	  --actor alice@example.com --source github \
//	  --since 2026-04-01T00:00:00Z
//
// --mode production is stubbed: returns an error until Phase 2 ships a
// checkpoint-backed store.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-investigate-tools: %v\n", err)
		os.Exit(1)
	}
}

// run is the testable entry point; it accepts the args slice so tests can call
// it directly without spawning a subprocess.
func run(args []string) error {
	fs := flag.NewFlagSet("mallcop-investigate-tools", flag.ContinueOnError)

	tool := fs.String("tool", "", "one of: check-baseline, search-events, search-findings (required)")
	mode := fs.String("mode", "exam", "exam (reads from --fixture-dir) or production (stubbed)")
	fixtureDir := fs.String("fixture-dir", "", "path to fixture directory (required in exam mode)")

	// check-baseline flags
	entity := fs.String("entity", "", "entity ID or email to look up (check-baseline)")
	source := fs.String("source", "", "source connector (check-baseline, search-events, search-findings)")
	hours := fs.Int("hours", 168, "look-back window in hours (check-baseline)")

	// search-events flags
	actor := fs.String("actor", "", "actor filter (search-events, search-findings)")
	evtType := fs.String("type", "", "event_type filter (search-events, optional)")
	since := fs.String("since", "", "RFC3339 start time inclusive (search-events, search-findings)")
	until := fs.String("until", "", "RFC3339 end time inclusive (search-events)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Accept trailing positional JSON argument (API tool executor convention).
	// When the last positional arg looks like JSON, parse it and apply any
	// recognized keys as flag overrides. This allows the binary to be called
	// both via named flags (CLI) and via JSON (API spawn path tool executor).
	if rest := fs.Args(); len(rest) > 0 {
		lastArg := rest[len(rest)-1]
		if len(lastArg) > 0 && lastArg[0] == '{' {
			var input map[string]interface{}
			if err := json.Unmarshal([]byte(lastArg), &input); err == nil {
				if v, ok := input["entity"].(string); ok && *entity == "" {
					*entity = v
				}
				if v, ok := input["source"].(string); ok && *source == "" {
					*source = v
				}
				if v, ok := input["actor"].(string); ok && *actor == "" {
					*actor = v
				}
				if v, ok := input["type"].(string); ok && *evtType == "" {
					*evtType = v
				}
				if v, ok := input["since"].(string); ok && *since == "" {
					*since = v
				}
				if v, ok := input["until"].(string); ok && *until == "" {
					*until = v
				}
				if v, ok := input["hours"].(float64); ok && *hours == 168 {
					*hours = int(v)
				}
			}
		}
	}

	if *tool == "" {
		return errors.New("--tool is required (check-baseline, search-events, search-findings)")
	}

	if *mode == "production" {
		// Phase 2: production path reads from a checkpoint-backed store.
		// Deferred — the store is not yet implemented.
		return errors.New("mode 'production' not yet implemented — use exam mode")
	}
	if *mode != "exam" {
		return fmt.Errorf("unknown --mode %q; use exam or production", *mode)
	}

	// Exam mode: fixture-dir is required.
	if *fixtureDir == "" {
		return errors.New("--fixture-dir is required in exam mode")
	}

	// Resolve the fixture dir to an absolute path and verify it exists.
	absFixtureDir, err := filepath.Abs(*fixtureDir)
	if err != nil {
		return fmt.Errorf("resolve fixture-dir: %w", err)
	}
	if _, err := os.Stat(absFixtureDir); err != nil {
		return fmt.Errorf("fixture-dir %q: %w", absFixtureDir, err)
	}

	switch *tool {
	case "check-baseline":
		return checkBaseline(absFixtureDir, *entity, *source, *hours)
	case "search-events":
		return searchEvents(absFixtureDir, *actor, *source, *evtType, *since, *until)
	case "search-findings":
		return searchFindings(absFixtureDir, *actor, *source, *since)
	default:
		return fmt.Errorf("unknown --tool %q; use check-baseline, search-events, or search-findings", *tool)
	}
}

// safeOpen resolves path relative to baseDir, rejects symlink escapes, and
// returns the open file. Returns a wrapped error with context on any failure.
func safeOpen(baseDir, relPath string) (*os.File, error) {
	joined := filepath.Join(baseDir, relPath)

	// Resolve symlinks. If the file doesn't exist yet (e.g. findings.jsonl),
	// EvalSymlinks will fail — we treat that as not-found rather than a security
	// error. The caller handles the not-found case.
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("resolve symlinks for %q: %w", joined, err)
	}

	// Enforce that the resolved path stays within baseDir.
	if !strings.HasPrefix(resolved, baseDir+string(filepath.Separator)) && resolved != baseDir {
		return nil, fmt.Errorf("path %q escapes fixture dir %q — rejected", resolved, baseDir)
	}

	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", resolved, err)
	}
	return f, nil
}

// ---- check-baseline --------------------------------------------------------

// baselineFile is the on-disk shape of baseline.json written by exam-seed.
type baselineFile struct {
	KnownEntities   knownEntities                `json:"known_entities"`
	FrequencyTables map[string]int               `json:"frequency_tables,omitempty"`
	Relationships   map[string]relationshipEntry `json:"relationships,omitempty"`
}

// knownEntities mirrors internal/exam.KnownEntities.
// NOTE: actor_roles is not present in the current KnownEntities type (Wave 3
// reviewer bfc flagged this as silently dropped data). We return an empty
// slice until internal/exam captures baseline.known_entities.actor_roles.
// TODO(mallcoppro-a97): populate ActorRoles from KnownEntities once upstream
// adds the field.
type knownEntities struct {
	Actors  []string `json:"actors"`
	Sources []string `json:"sources"`
}

// relationshipEntry mirrors internal/exam.RelationshipEntry.
type relationshipEntry struct {
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// baselineResult is the JSON output contract for check-baseline.
type baselineResult struct {
	Known     bool     `json:"known"`
	LastSeen  string   `json:"last_seen"`
	Frequency int      `json:"frequency"`
	Roles     []string `json:"roles"`
}

func checkBaseline(fixtureDir, entity, source string, hours int) error {
	if entity == "" {
		return errors.New("--entity is required for check-baseline")
	}

	f, err := safeOpen(fixtureDir, "baseline.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No baseline file — entity is unknown.
			return emitJSON(baselineResult{Known: false, Roles: []string{}})
		}
		return fmt.Errorf("open baseline.json: %w", err)
	}
	defer f.Close()

	var bl baselineFile
	if err := json.NewDecoder(f).Decode(&bl); err != nil {
		return fmt.Errorf("decode baseline.json: %w", err)
	}

	// Check if entity appears in known actors.
	known := false
	for _, a := range bl.KnownEntities.Actors {
		if strings.EqualFold(a, entity) {
			known = true
			break
		}
	}

	// If source is provided, also require the source to be known.
	if known && source != "" {
		sourceKnown := false
		for _, s := range bl.KnownEntities.Sources {
			if strings.EqualFold(s, source) {
				sourceKnown = true
				break
			}
		}
		if !sourceKnown {
			known = false
		}
	}

	// Frequency: check frequency_tables for the entity key.
	freq := 0
	if bl.FrequencyTables != nil {
		if v, ok := bl.FrequencyTables[entity]; ok {
			freq = v
		}
	}

	// Last seen: derive from relationships map (key = "actor:target" or "actor").
	lastSeen := ""
	if bl.Relationships != nil {
		// Prefer an exact actor key match; fall back to any key containing entity.
		if rel, ok := bl.Relationships[entity]; ok {
			lastSeen = rel.LastSeen
		} else {
			// Check within the look-back window.
			windowStart := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
			for key, rel := range bl.Relationships {
				if !strings.Contains(strings.ToLower(key), strings.ToLower(entity)) {
					continue
				}
				if rel.LastSeen == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, rel.LastSeen)
				if err != nil {
					continue
				}
				if t.After(windowStart) {
					lastSeen = rel.LastSeen
					break
				}
			}
		}
	}

	// TODO(mallcoppro-a97): populate roles from KnownEntities.actor_roles once
	// internal/exam captures that field. Currently always empty slice.
	roles := []string{}

	return emitJSON(baselineResult{
		Known:     known,
		LastSeen:  lastSeen,
		Frequency: freq,
		Roles:     roles,
	})
}

// ---- search-events ---------------------------------------------------------

// fixtureEventsFile is the on-disk shape of events.json written by exam-seed.
type fixtureEventsFile struct {
	Events []rawEvent `json:"events"`
}

// rawEvent is the JSON shape of an event entry in events.json.
// We use a map for Metadata/Raw to avoid dependency on internal/exam.
type rawEvent struct {
	ID         string                 `json:"id"`
	Timestamp  string                 `json:"timestamp"`
	IngestedAt string                 `json:"ingested_at"`
	Source     string                 `json:"source"`
	EventType  string                 `json:"event_type"`
	Actor      string                 `json:"actor"`
	Action     string                 `json:"action"`
	Target     string                 `json:"target"`
	Severity   string                 `json:"severity"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Raw        interface{}            `json:"raw,omitempty"`
}

func searchEvents(fixtureDir, actor, source, evtType, since, until string) error {
	f, err := safeOpen(fixtureDir, "events.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Empty result is valid.
			return nil
		}
		return fmt.Errorf("open events.json: %w", err)
	}
	defer f.Close()

	var ef fixtureEventsFile
	if err := json.NewDecoder(f).Decode(&ef); err != nil {
		return fmt.Errorf("decode events.json: %w", err)
	}

	var sinceT, untilT time.Time
	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return fmt.Errorf("parse --since: %w", err)
		}
		sinceT = t
	}
	if until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return fmt.Errorf("parse --until: %w", err)
		}
		untilT = t
	}

	enc := json.NewEncoder(os.Stdout)
	for _, ev := range ef.Events {
		if actor != "" && !strings.EqualFold(ev.Actor, actor) {
			continue
		}
		if source != "" && !strings.EqualFold(ev.Source, source) {
			continue
		}
		if evtType != "" && !strings.EqualFold(ev.EventType, evtType) {
			continue
		}
		if !sinceT.IsZero() || !untilT.IsZero() {
			if ev.Timestamp == "" {
				continue
			}
			ts, err := time.Parse(time.RFC3339, ev.Timestamp)
			if err != nil {
				// Try without seconds precision.
				ts, err = time.Parse("2006-01-02T15:04:05Z", ev.Timestamp)
				if err != nil {
					continue
				}
			}
			if !sinceT.IsZero() && ts.Before(sinceT) {
				continue
			}
			if !untilT.IsZero() && ts.After(untilT) {
				continue
			}
		}
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}
	return nil
}

// ---- search-findings -------------------------------------------------------

func searchFindings(fixtureDir, actor, source, since string) error {
	f, err := safeOpen(fixtureDir, "findings.jsonl")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// findings.jsonl may not exist yet — empty result is valid.
			return nil
		}
		return fmt.Errorf("open findings.jsonl: %w", err)
	}
	defer f.Close()

	var sinceT time.Time
	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return fmt.Errorf("parse --since: %w", err)
		}
		sinceT = t
	}

	dec := json.NewDecoder(f)
	enc := json.NewEncoder(os.Stdout)
	for dec.More() {
		var finding map[string]interface{}
		if err := dec.Decode(&finding); err != nil {
			return fmt.Errorf("decode findings.jsonl: %w", err)
		}
		if actor != "" {
			a, _ := finding["actor"].(string)
			if !strings.EqualFold(a, actor) {
				continue
			}
		}
		if source != "" {
			s, _ := finding["source"].(string)
			if !strings.EqualFold(s, source) {
				continue
			}
		}
		if !sinceT.IsZero() {
			ts := ""
			for _, key := range []string{"timestamp", "created_at", "detected_at"} {
				if v, ok := finding[key].(string); ok && v != "" {
					ts = v
					break
				}
			}
			if ts == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				continue
			}
			if t.Before(sinceT) {
				continue
			}
		}
		if err := enc.Encode(finding); err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
	}
	return nil
}

// ---- helpers ---------------------------------------------------------------

func emitJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
