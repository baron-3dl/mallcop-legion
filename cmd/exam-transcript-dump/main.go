// cmd/exam-transcript-dump renders a judge-visible Markdown transcript from
// exam fixture data and a heal disposition's resolution JSON.
//
// Usage:
//
//	exam-transcript-dump \
//	  --scenario-id <id> \
//	  --fixture-dir  <path>  \
//	  --transcript-dir <path> \
//	  --resolution-json '<json>' | @<path>
//
// The command reads <fixture-dir>/events.json and <fixture-dir>/baseline.json,
// combines them with the resolution JSON, and emits
// <transcript-dir>/<scenario-id>.md.
//
// Defense-in-depth sanitization: before writing, the rendered buffer is
// scanned for forbidden substrings (ground-truth field names that must never
// reach a judge). If any are detected the command exits with an error and
// writes nothing to disk.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// forbidden lists substrings that MUST NOT appear in judge-visible output.
// Both snake_case and CamelCase variants are included because the heal
// actor may echo either form from the Scenario struct.
//
// Taxonomy failure-mode codes (KA, AE, CS, NE, VN, TT) are checked via
// whole-word regex rather than substring match to avoid false positives on
// words like "neat" or "token". The regex check is applied after the
// substring scan and uses \b word-boundary anchors for precision.
var forbidden = []string{
	"trap_description",
	"trap_resolved_means",
	"expected_resolution",
	"TrapDescription",
	"TrapResolvedMeans",
	"ExpectedResolution",
}

// taxonomyCodes are the six failure-mode codes from the exam taxonomy.
// They identify which trap class a scenario belongs to and must never
// appear in the transcript (the judge is blind to scenario classification).
// Word-boundary regex is used (not substring) to avoid matching common
// English prefixes/suffixes that happen to contain these two-letter codes.
var taxonomyCodes = []string{"KA", "AE", "CS", "NE", "VN", "TT"}

// compileTaxonomyRegex returns a single compiled regexp that matches any of
// the taxonomy codes as a standalone word (upper-case, word-boundary).
func compileTaxonomyRegex() *regexp.Regexp {
	alts := make([]string, len(taxonomyCodes))
	for i, code := range taxonomyCodes {
		alts[i] = `\b` + regexp.QuoteMeta(code) + `\b`
	}
	return regexp.MustCompile(strings.Join(alts, "|"))
}

var taxonomyRE = compileTaxonomyRegex()

// Event is the JSON representation written by exam-seed to events.json.
// We use a flexible map for metadata/raw to avoid version-skew brittleness.
type Event struct {
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Severity  string         `json:"severity"`
	Metadata  map[string]any `json:"metadata"`
}

// Baseline is the JSON representation of baseline state from baseline.json.
type Baseline struct {
	KnownEntities struct {
		Actors  []string `json:"actors"`
		Sources []string `json:"sources"`
	} `json:"known_entities"`
	FrequencyTables map[string]int            `json:"frequency_tables"`
	Relationships   map[string]map[string]any `json:"relationships"`
}

// Finding holds the sanitized finding fields written to events.json by exam-seed.
// Only public-safe fields (no ground-truth) are expected here.
type Finding struct {
	ID       string         `json:"id"`
	Detector string         `json:"detector"`
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	EventIDs []string       `json:"event_ids"`
	Metadata map[string]any `json:"metadata"`
}

// FixtureEnvelope is the envelope format used by exam-seed for events.json.
// It carries the sanitized finding alongside the events list.
type FixtureEnvelope struct {
	Finding Finding `json:"finding"`
	Events  []Event `json:"events"`
}

const transcriptTmpl = `# Exam Transcript — {{ .ScenarioID }}

## Scenario Finding (sanitized)

| Field    | Value |
|----------|-------|
| Finding  | {{ .FindingID }} |
| Detector | {{ .Detector }} |
| Title    | {{ .Title }} |
| Severity | {{ .Severity }} |

## Events

{{ range .Events -}}
### Event {{ .ID }}

| Field      | Value |
|------------|-------|
| Timestamp  | {{ .Timestamp }} |
| Source     | {{ .Source }} |
| Type       | {{ .EventType }} |
| Actor      | {{ .Actor }} |
| Action     | {{ .Action }} |
| Target     | {{ .Target }} |
| Severity   | {{ .Severity }} |

{{ end -}}
## Baseline

**Known Actors:** {{ join .KnownActors ", " }}

**Known Sources:** {{ join .KnownSources ", " }}

{{ if .FreqRows -}}
**Frequency Tables:**

| Key | Count |
|-----|-------|
{{ range .FreqRows -}}
| {{ .Key }} | {{ .Count }} |
{{ end }}
{{- end -}}

## Actor Chain (Phase 1 placeholder)

{{ if .ActorChain -}}
{{ .ActorChain }}
{{- else -}}
*Actor chain not available for this run. Resolution JSON summary follows.*
{{- end }}

## Final Resolution

{{ .ResolutionSummary }}
`

type freqRow struct {
	Key   string
	Count int
}

type transcriptData struct {
	ScenarioID        string
	FindingID         string
	Detector          string
	Title             string
	Severity          string
	Events            []Event
	KnownActors       []string
	KnownSources      []string
	FreqRows          []freqRow
	ActorChain        string
	ResolutionSummary string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "exam-transcript-dump: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	scenarioID := flag.String("scenario-id", "", "scenario ID (required)")
	fixtureDir := flag.String("fixture-dir", "", "directory containing events.json and baseline.json (required)")
	transcriptDir := flag.String("transcript-dir", "", "directory to write <scenario-id>.md (required)")
	resolutionJSON := flag.String("resolution-json", "", "heal disposition output: inline JSON or @/path/to/file.json (required)")
	flag.Parse()

	if *scenarioID == "" {
		return fmt.Errorf("--scenario-id is required")
	}
	if *fixtureDir == "" {
		return fmt.Errorf("--fixture-dir is required")
	}
	if *transcriptDir == "" {
		return fmt.Errorf("--transcript-dir is required")
	}
	if *resolutionJSON == "" {
		return fmt.Errorf("--resolution-json is required")
	}

	// 1. Read fixture files.
	eventsPath := filepath.Join(*fixtureDir, "events.json")
	baselinePath := filepath.Join(*fixtureDir, "baseline.json")

	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		return fmt.Errorf("read events.json: %w", err)
	}
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return fmt.Errorf("read baseline.json: %w", err)
	}

	var envelope FixtureEnvelope
	if err := json.Unmarshal(eventsData, &envelope); err != nil {
		return fmt.Errorf("parse events.json: %w", err)
	}

	var bl Baseline
	if err := json.Unmarshal(baselineData, &bl); err != nil {
		return fmt.Errorf("parse baseline.json: %w", err)
	}

	// 2. Load resolution JSON (inline or @path).
	rawResolution, err := loadResolutionJSON(*resolutionJSON)
	if err != nil {
		return fmt.Errorf("load resolution-json: %w", err)
	}

	var resMap map[string]any
	if err := json.Unmarshal(rawResolution, &resMap); err != nil {
		return fmt.Errorf("parse resolution JSON: %w", err)
	}

	// 3. Build transcript data.
	data, err := buildTranscriptData(*scenarioID, envelope, bl, resMap)
	if err != nil {
		return fmt.Errorf("build transcript: %w", err)
	}

	// Render to buffer.
	buf, err := renderTranscript(data)
	if err != nil {
		return fmt.Errorf("render transcript: %w", err)
	}

	// 4. Defense-in-depth scan BEFORE writing.
	if err := scanForForbidden(buf); err != nil {
		return fmt.Errorf("SANITIZATION FAILURE — refusing to write poisoned transcript: %w", err)
	}

	// 5. Write output.
	if err := os.MkdirAll(*transcriptDir, 0o755); err != nil {
		return fmt.Errorf("mkdir transcript-dir: %w", err)
	}
	outPath := filepath.Join(*transcriptDir, *scenarioID+".md")
	if err := os.WriteFile(outPath, []byte(buf), 0o644); err != nil {
		return fmt.Errorf("write transcript: %w", err)
	}

	// 6. Print path for downstream callers.
	fmt.Println(outPath)
	return nil
}

// loadResolutionJSON reads the resolution JSON from an inline string or a file
// (when the value starts with '@').
func loadResolutionJSON(s string) ([]byte, error) {
	if strings.HasPrefix(s, "@") {
		path := s[1:]
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read @file %s: %w", path, err)
		}
		return data, nil
	}
	return []byte(s), nil
}

// buildTranscriptData assembles the template model from parsed fixture data and
// the resolution map.
func buildTranscriptData(scenarioID string, env FixtureEnvelope, bl Baseline, resMap map[string]any) (transcriptData, error) {
	// Stable sort of frequency table rows.
	var rows []freqRow
	for k, v := range bl.FrequencyTables {
		rows = append(rows, freqRow{Key: k, Count: v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })

	// Stable sort of known actors and sources.
	actors := append([]string(nil), bl.KnownEntities.Actors...)
	sources := append([]string(nil), bl.KnownEntities.Sources...)
	sort.Strings(actors)
	sort.Strings(sources)

	// Stable sort of events (should already be ordered, but enforce it).
	events := append([]Event(nil), env.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })

	// Extract actor chain from resolution if present.
	actorChain := extractActorChain(resMap)

	// Build resolution summary from known safe fields.
	summary := buildResolutionSummary(resMap)

	return transcriptData{
		ScenarioID:        scenarioID,
		FindingID:         env.Finding.ID,
		Detector:          env.Finding.Detector,
		Title:             env.Finding.Title,
		Severity:          env.Finding.Severity,
		Events:            events,
		KnownActors:       actors,
		KnownSources:      sources,
		FreqRows:          rows,
		ActorChain:        actorChain,
		ResolutionSummary: summary,
	}, nil
}

// extractActorChain pulls triage/investigate/heal reasoning from the resolution
// map if present. Returns empty string if none of the known fields are found.
func extractActorChain(res map[string]any) string {
	var parts []string
	for _, key := range []string{"reasoning", "thoughts", "steps", "rationale", "actor_chain"} {
		if v, ok := res[key]; ok {
			parts = append(parts, fmt.Sprintf("**%s:** %v", key, v))
		}
	}
	return strings.Join(parts, "\n\n")
}

// buildResolutionSummary renders safe verdict fields as a Markdown table.
// It explicitly skips any key that matches a forbidden name to provide an
// extra layer of sanitization within the data model itself.
func buildResolutionSummary(res map[string]any) string {
	// Keys to render first (stable order for determinism).
	priority := []string{
		"action", "verdict", "confidence", "chain_action", "triage_action",
		"disposition", "summary", "reasoning", "thoughts", "steps", "rationale",
	}

	// Collect keys: priority keys first, then remaining keys alphabetically.
	seen := map[string]bool{}
	var keys []string
	for _, k := range priority {
		if _, ok := res[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range res {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)

	var sb strings.Builder
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("|-------|-------|\n")
	for _, k := range keys {
		// Skip any key whose name is itself forbidden — defense-in-depth within
		// the data model before we even hit the final buffer scan.
		if isForbiddenKey(k) {
			continue
		}
		sb.WriteString(fmt.Sprintf("| %s | %v |\n", k, res[k]))
	}
	return sb.String()
}

// isForbiddenKey returns true if the key name matches any forbidden substring.
func isForbiddenKey(k string) bool {
	lower := strings.ToLower(k)
	for _, f := range forbidden {
		if strings.Contains(lower, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

// renderTranscript executes the template and returns the rendered string.
func renderTranscript(data transcriptData) (string, error) {
	funcMap := template.FuncMap{
		"join": strings.Join,
	}
	tmpl, err := template.New("transcript").Funcs(funcMap).Parse(transcriptTmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return sb.String(), nil
}

// scanForForbidden checks the rendered buffer for forbidden substrings and
// taxonomy code whole-words. Returns an error if any are found.
//
// Design choice: ERROR on dirty input (refuse to write). The input should
// already be clean (exam-seed strips at emission). The transcript writer is
// the last chokepoint — if something leaked through, we return an error
// rather than silently emitting a poisoned transcript. This surfaces the
// problem loudly so the pipeline can be fixed upstream.
func scanForForbidden(buf string) error {
	// 1. Substring check for ground-truth field names.
	for _, f := range forbidden {
		if strings.Contains(buf, f) {
			return fmt.Errorf("forbidden substring %q found in rendered transcript", f)
		}
	}

	// 2. Whole-word regex check for taxonomy failure-mode codes.
	// Rationale for word-boundary regex over substring: the codes (KA, AE, CS,
	// NE, VN, TT) are two-letter sequences that appear naturally in English text
	// ("neat", "token", "aces", "vane"). Substring matching would produce too
	// many false positives and would block legitimate transcripts. Word-boundary
	// (\b) anchors restrict matches to standalone codes, which are the dangerous
	// form — a bare "KA" or "AE" in a transcript reveals the failure-mode class
	// to the judge.
	if loc := taxonomyRE.FindStringIndex(buf); loc != nil {
		found := buf[loc[0]:loc[1]]
		return fmt.Errorf("forbidden taxonomy code %q found in rendered transcript", found)
	}

	return nil
}
