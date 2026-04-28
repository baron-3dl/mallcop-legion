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
//	mallcop-investigate-tools --tool baseline-stats \
//	  --mode exam --fixture-dir /path/to/fixture \
//	  --entity alice@example.com --source github
//
//	mallcop-investigate-tools --tool read-config \
//	  --mode exam --fixture-dir /path/to/fixture \
//	  --detector my-detector --connector github
//
//	mallcop-investigate-tools --tool load-skill \
//	  --skill-name aws-iam
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

	"gopkg.in/yaml.v3"
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

	tool := fs.String("tool", "", "one of: check-baseline, search-events, search-findings, read-finding, baseline-stats, read-config, load-skill (required)")
	mode := fs.String("mode", "exam", "exam (reads from --fixture-dir) or production (stubbed)")
	fixtureDir := fs.String("fixture-dir", "", "path to fixture directory (required in exam mode for fixture-based tools)")

	// check-baseline / baseline-stats flags
	entity := fs.String("entity", "", "entity ID or email to look up (check-baseline, baseline-stats)")
	source := fs.String("source", "", "source connector (check-baseline, search-events, search-findings, baseline-stats, read-config)")
	hours := fs.Int("hours", 168, "look-back window in hours (check-baseline)")

	// search-events flags
	actor := fs.String("actor", "", "actor filter (search-events, search-findings)")
	evtType := fs.String("type", "", "event_type filter (search-events, optional)")
	since := fs.String("since", "", "RFC3339 start time inclusive (search-events, search-findings)")
	until := fs.String("until", "", "RFC3339 end time inclusive (search-events)")

	// read-finding flags
	findingID := fs.String("finding-id", "", "finding ID to read (read-finding)")

	// read-config flags
	detector := fs.String("detector", "", "detector name filter (read-config, optional)")
	connector := fs.String("connector", "", "connector name filter (read-config, optional)")

	// load-skill flags
	skillName := fs.String("skill-name", "", "skill name filter (load-skill, optional)")
	sourceHint := fs.String("source-hint", "", "source hint filter (load-skill, optional)")

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
				if v, ok := input["finding_id"].(string); ok && *findingID == "" {
					*findingID = v
				}
				if v, ok := input["detector"].(string); ok && *detector == "" {
					*detector = v
				}
				if v, ok := input["connector"].(string); ok && *connector == "" {
					*connector = v
				}
				if v, ok := input["skill_name"].(string); ok && *skillName == "" {
					*skillName = v
				}
				if v, ok := input["source_hint"].(string); ok && *sourceHint == "" {
					*sourceHint = v
				}
			}
		}
	}

	if *tool == "" {
		return errors.New("--tool is required (check-baseline, search-events, search-findings, read-finding, baseline-stats, read-config, load-skill, or an F1G action tool)")
	}

	// load-skill is a catalog-only discovery tool — no fixture-dir or mode needed.
	if *tool == "load-skill" {
		return loadSkill(*skillName, *sourceHint)
	}

	// F1G action tools: dispatch before mode/fixture-dir checks.
	// They read input from the trailing positional JSON argument (set by the
	// API tool executor) and emit side-effects via cf + rd.
	if actionTools[*tool] {
		// Collect the positional JSON input (last arg, if present and JSON-shaped).
		var inputJSON string
		if rest := fs.Args(); len(rest) > 0 {
			last := rest[len(rest)-1]
			if len(last) > 0 && last[0] == '{' {
				inputJSON = last
			}
		}
		return dispatchActionTool(*tool, inputJSON)
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
	case "read-finding":
		return readFinding(absFixtureDir, *findingID)
	case "baseline-stats":
		return baselineStats(absFixtureDir, *entity, *source)
	case "read-config":
		return readConfig(absFixtureDir, *detector, *connector)
	default:
		return fmt.Errorf("unknown --tool %q; use check-baseline, search-events, search-findings, read-finding, baseline-stats, read-config, load-skill, or an F1G action tool", *tool)
	}
}

// actionTools is the set of tool names that are action/side-effect tools (F1G).
// These read JSON input from the trailing positional argument (API path convention)
// and do NOT require --fixture-dir or --mode.
var actionTools = map[string]bool{
	// F1G-a: Finding-state tools
	"resolve-finding":  true,
	"annotate-finding": true,
	// F1G-b: Chain-handoff tools
	"escalate-to-investigator":  true,
	"escalate-to-stage-c":       true,
	"escalate-to-deep":          true,
	"create-investigate-merge":  true,
	"write-partial-transcript":  true,
	// F1G-c: Operator/escalation tools
	"list-actions":      true,
	"remediate-action":  true,
	"request-approval":  true,
	"message-operator":  true,
	// F1G-d: Approve-action tool
	"approve-action": true,
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

// ---- read-finding ----------------------------------------------------------

// readFinding returns the full finding record for the given finding_id from
// findings.jsonl. Returns {"error":"not_found","finding_id":"..."} if the
// finding does not exist in the fixture. Returns an error if findings.jsonl
// cannot be opened or parsed.
func readFinding(fixtureDir, findingID string) error {
	if findingID == "" {
		return errors.New("--finding-id is required for read-finding")
	}

	f, err := safeOpen(fixtureDir, "findings.jsonl")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return emitJSON(map[string]interface{}{
				"error":      "not_found",
				"finding_id": findingID,
			})
		}
		return fmt.Errorf("open findings.jsonl: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for dec.More() {
		var finding map[string]interface{}
		if err := dec.Decode(&finding); err != nil {
			return fmt.Errorf("decode findings.jsonl: %w", err)
		}
		id, _ := finding["finding_id"].(string)
		if id == "" {
			// Also check "id" key variant.
			id, _ = finding["id"].(string)
		}
		if strings.EqualFold(id, findingID) {
			return emitJSON(finding)
		}
	}

	return emitJSON(map[string]interface{}{
		"error":      "not_found",
		"finding_id": findingID,
	})
}

// ---- baseline-stats --------------------------------------------------------

// baselineStatsResult is the JSON output contract for baseline-stats.
type baselineStatsResult struct {
	CountTotal            int            `json:"count_total"`
	CountBySource         map[string]int `json:"count_by_source"`
	CountByType           map[string]int `json:"count_by_type"`
	TimeOfDayDistribution map[string]int `json:"time_of_day_distribution"`
	WeekdayDistribution   map[string]int `json:"weekday_distribution"`
	FirstSeen             *string        `json:"first_seen"`
	LastSeen              *string        `json:"last_seen"`
}

// newEmptyBaselineStatsResult returns a zeroed baselineStatsResult with
// initialized maps and nil timestamps (per spec: null when no events match).
func newEmptyBaselineStatsResult() baselineStatsResult {
	tod := make(map[string]int, 24)
	for h := 0; h < 24; h++ {
		tod[fmt.Sprintf("%02d", h)] = 0
	}
	wd := map[string]int{
		"mon": 0, "tue": 0, "wed": 0, "thu": 0,
		"fri": 0, "sat": 0, "sun": 0,
	}
	return baselineStatsResult{
		CountTotal:            0,
		CountBySource:         map[string]int{},
		CountByType:           map[string]int{},
		TimeOfDayDistribution: tod,
		WeekdayDistribution:   wd,
		FirstSeen:             nil,
		LastSeen:              nil,
	}
}

// weekdayKey maps time.Weekday to the lowercase 3-letter key used in the output.
func weekdayKey(d time.Weekday) string {
	switch d {
	case time.Monday:
		return "mon"
	case time.Tuesday:
		return "tue"
	case time.Wednesday:
		return "wed"
	case time.Thursday:
		return "thu"
	case time.Friday:
		return "fri"
	case time.Saturday:
		return "sat"
	default:
		return "sun"
	}
}

// baselineStats aggregates statistics from the baseline.json fixture.
// The fixture used here is events-shaped: a JSON array of records with at
// minimum {actor, source, timestamp, type}.  It falls back to zero results
// if the file is absent (same graceful-not-found behaviour as check-baseline).
func baselineStats(fixtureDir, entity, source string) error {
	f, err := safeOpen(fixtureDir, "baseline.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return emitJSON(newEmptyBaselineStatsResult())
		}
		return fmt.Errorf("open baseline.json: %w", err)
	}
	defer f.Close()

	// baseline.json may be an event-array OR the structured baseline file used by
	// check-baseline.  Try to decode as an array first; fall back to the struct.
	var rawData json.RawMessage
	if err := json.NewDecoder(f).Decode(&rawData); err != nil {
		return fmt.Errorf("decode baseline.json: %w", err)
	}

	// Try as a flat event array.
	type eventRecord struct {
		Actor     string `json:"actor"`
		Source    string `json:"source"`
		Type      string `json:"type"`
		Timestamp string `json:"timestamp"`
	}
	var events []eventRecord
	if err := json.Unmarshal(rawData, &events); err != nil {
		// Not an array — the fixture is in check-baseline struct format.
		// Return empty stats rather than error; stats require event records.
		return emitJSON(newEmptyBaselineStatsResult())
	}

	result := newEmptyBaselineStatsResult()

	for _, ev := range events {
		// Apply optional filters.
		if entity != "" && !strings.EqualFold(ev.Actor, entity) {
			continue
		}
		if source != "" && !strings.EqualFold(ev.Source, source) {
			continue
		}

		result.CountTotal++

		if ev.Source != "" {
			result.CountBySource[ev.Source]++
		}
		if ev.Type != "" {
			result.CountByType[ev.Type]++
		}

		if ev.Timestamp != "" {
			t, err := time.Parse(time.RFC3339, ev.Timestamp)
			if err == nil {
				// Time-of-day bucket (hour, zero-padded).
				hourKey := fmt.Sprintf("%02d", t.UTC().Hour())
				result.TimeOfDayDistribution[hourKey]++

				// Weekday bucket.
				result.WeekdayDistribution[weekdayKey(t.UTC().Weekday())]++

				// first_seen / last_seen tracking.
				if result.FirstSeen == nil || ev.Timestamp < *result.FirstSeen {
					ts := ev.Timestamp
					result.FirstSeen = &ts
				}
				if result.LastSeen == nil || ev.Timestamp > *result.LastSeen {
					ts := ev.Timestamp
					result.LastSeen = &ts
				}
			}
		}
	}

	return emitJSON(result)
}

// ---- read-config -----------------------------------------------------------

// configFile is the on-disk shape of config.json.
type configFile struct {
	Detectors  map[string]json.RawMessage `json:"detectors"`
	Connectors map[string]json.RawMessage `json:"connectors"`
}

// configResult is the JSON output contract for read-config.
type configResult struct {
	Detectors  map[string]json.RawMessage `json:"detectors"`
	Connectors map[string]json.RawMessage `json:"connectors"`
}

// readConfig reads connector and detector configuration from config.json.
// Returns an empty result if the file is absent (normal boot state).
func readConfig(fixtureDir, detector, connector string) error {
	f, err := safeOpen(fixtureDir, "config.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return emitJSON(configResult{
				Detectors:  map[string]json.RawMessage{},
				Connectors: map[string]json.RawMessage{},
			})
		}
		return fmt.Errorf("open config.json: %w", err)
	}
	defer f.Close()

	var cfg configFile
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return fmt.Errorf("decode config.json: %w", err)
	}

	result := configResult{
		Detectors:  map[string]json.RawMessage{},
		Connectors: map[string]json.RawMessage{},
	}

	// If no filters, return everything.
	if detector == "" && connector == "" {
		result.Detectors = cfg.Detectors
		result.Connectors = cfg.Connectors
		return emitJSON(result)
	}

	// Apply detector filter.
	if detector != "" {
		if cfg.Detectors != nil {
			if v, ok := cfg.Detectors[detector]; ok {
				result.Detectors[detector] = v
			}
		}
	} else {
		result.Detectors = cfg.Detectors
	}

	// Apply connector filter.
	if connector != "" {
		if cfg.Connectors != nil {
			if v, ok := cfg.Connectors[connector]; ok {
				result.Connectors[connector] = v
			}
		}
	} else {
		result.Connectors = cfg.Connectors
	}

	return emitJSON(result)
}

// ---- load-skill ------------------------------------------------------------

// skillCatalog is the on-disk shape of config/skill-catalog.yaml.
type skillCatalog struct {
	Skills []skillEntry `yaml:"skills"`
}

// skillTool is a single tool entry within a skill.
type skillTool struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
}

// skillEntry is a single skill in the catalog.
type skillEntry struct {
	Name        string      `yaml:"name" json:"name"`
	Version     string      `yaml:"version" json:"version"`
	Source      string      `yaml:"source,omitempty" json:"source,omitempty"`
	Description string      `yaml:"description" json:"description"`
	Status      string      `yaml:"status" json:"status"`
	Binding     string      `yaml:"binding" json:"binding"`
	Tools       []skillTool `yaml:"tools,omitempty" json:"tools,omitempty"`
	NotesFile   string      `yaml:"notes_file,omitempty" json:"notes_file,omitempty"`
}

// loadSkillResult is the JSON output contract for load-skill.
type loadSkillResult struct {
	Skills      []skillEntry `json:"skills"`
	BindingNote string       `json:"binding_note"`
}

const skillBindingNote = "Tools listed here are statically registered in the operational chart's tool_allowlist. " +
	"Calling load-skill is a discovery operation; it does not register new tools at runtime."

// resolveRepoRoot returns the repo root directory.
// Resolution order:
//  1. MALLCOP_REPO_ROOT env var (set by the engine in operational mode)
//  2. CWD (consistent with the path-resolution pattern in the existing tools)
func resolveRepoRoot() (string, error) {
	if v := os.Getenv("MALLCOP_REPO_ROOT"); v != "" {
		return filepath.Abs(v)
	}
	return os.Getwd()
}

// loadSkill reads the skill catalog from config/skill-catalog.yaml (repo-relative)
// and returns the matching entries.  Filters by skill_name (exact match) or
// source_hint (case-insensitive match on the source field).
// Returns an empty skills list when the catalog file is absent (normal at boot).
func loadSkill(skillName, sourceHint string) error {
	repoRoot, err := resolveRepoRoot()
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}

	catalogPath := filepath.Join(repoRoot, "config", "skill-catalog.yaml")
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return emitJSON(loadSkillResult{
				Skills:      []skillEntry{},
				BindingNote: skillBindingNote,
			})
		}
		return fmt.Errorf("read skill-catalog.yaml: %w", err)
	}

	var catalog skillCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return fmt.Errorf("parse skill-catalog.yaml: %w", err)
	}

	// Filter skills.
	filtered := []skillEntry{}
	for _, s := range catalog.Skills {
		if skillName != "" && s.Name != skillName {
			continue
		}
		if sourceHint != "" && !strings.EqualFold(s.Source, sourceHint) {
			continue
		}
		filtered = append(filtered, s)
	}

	// If no filters applied, return all skills (nil slice → empty array in JSON).
	if skillName == "" && sourceHint == "" {
		filtered = catalog.Skills
		if filtered == nil {
			filtered = []skillEntry{}
		}
	}

	return emitJSON(loadSkillResult{
		Skills:      filtered,
		BindingNote: skillBindingNote,
	})
}

// ---- helpers ---------------------------------------------------------------

func emitJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
