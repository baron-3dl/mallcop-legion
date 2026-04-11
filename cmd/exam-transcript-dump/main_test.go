package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixtures writes events.json and baseline.json to dir.
func writeFixtures(t *testing.T, dir string, envelope FixtureEnvelope, bl Baseline) {
	t.Helper()

	evData, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal events.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.json"), evData, 0o644); err != nil {
		t.Fatalf("write events.json: %v", err)
	}

	blData, err := json.Marshal(bl)
	if err != nil {
		t.Fatalf("marshal baseline.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "baseline.json"), blData, 0o644); err != nil {
		t.Fatalf("write baseline.json: %v", err)
	}
}

// cleanEnvelope returns a minimal, trap-free fixture envelope for testing.
func cleanEnvelope() FixtureEnvelope {
	return FixtureEnvelope{
		Finding: Finding{
			ID:       "fnd_shk_001",
			Detector: "new-actor",
			Title:    "New actor observed: deploy-svc-new",
			Severity: "warn",
			EventIDs: []string{"evt_001", "evt_002"},
		},
		Events: []Event{
			{
				ID:        "evt_001",
				Timestamp: "2026-03-10T14:22:00Z",
				Source:    "azure",
				EventType: "service_principal_created",
				Actor:     "admin-user",
				Action:    "create_service_principal",
				Target:    "acme-corp/service-principals/deploy-svc-new",
				Severity:  "info",
			},
			{
				ID:        "evt_002",
				Timestamp: "2026-03-10T14:25:00Z",
				Source:    "azure",
				EventType: "role_assignment",
				Actor:     "admin-user",
				Action:    "add_role_assignment",
				Target:    "sub-169efd95/resourceGroups/atom-rg",
				Severity:  "info",
			},
		},
	}
}

// cleanBaseline returns a minimal baseline matching ID-01.
func cleanBaseline() Baseline {
	var bl Baseline
	bl.KnownEntities.Actors = []string{"admin-user", "ci-bot", "deploy-svc", "tf-automation"}
	bl.KnownEntities.Sources = []string{"azure", "github"}
	bl.FrequencyTables = map[string]int{
		"azure:login:admin-user":                    412,
		"azure:role_assignment:admin-user":          28,
		"azure:service_principal_created:admin-user": 5,
	}
	return bl
}

// cleanResolutionJSON returns a heal disposition JSON that contains NO ground-truth leakage.
func cleanResolutionJSON() map[string]any {
	return map[string]any{
		"action":     "resolved",
		"confidence": "high",
		"reasoning":  "Admin-user created a new service principal during business hours with a non-privileged role. Context is consistent with standard onboarding.",
		"summary":    "Resolved as benign onboarding.",
	}
}

// TestDump_TrapStuffedInputSanitized verifies that the dumper REFUSES to write
// a transcript when forbidden ground-truth substrings have leaked into the input.
//
// The test embeds "trap_description" into:
//   - finding.title (via the envelope)
//   - event[0].action
//   - event[1].target
//   - resolution JSON as both a key name ("ExpectedResolution") and a value string
//
// Expected behavior: scanForForbidden detects the forbidden substring before
// writing and returns an error. The output file is NOT created.
// This matches the "error on dirty input" design choice documented in scanForForbidden.
func TestDump_TrapStuffedInputSanitized(t *testing.T) {
	fixtureDir := t.TempDir()
	transcriptDir := t.TempDir()

	// Build a stuffed envelope: poison injected in multiple locations.
	stuffed := cleanEnvelope()
	stuffed.Finding.Title = "trap_description: admin-user created svc"
	stuffed.Events[0].Action = "create_service_principal (trap_description embedded)"
	stuffed.Events[1].Target = "sub-169efd95/trap_resolved_means/atom-rg"

	writeFixtures(t, fixtureDir, stuffed, cleanBaseline())

	// Resolution JSON with a forbidden key AND a forbidden value.
	resMap := cleanResolutionJSON()
	resMap["ExpectedResolution"] = "chain_action=resolved"
	resBytes, _ := json.Marshal(resMap)

	err := run2("ID-01-new-actor-benign-onboarding", fixtureDir, transcriptDir, string(resBytes))

	// The dumper MUST return an error — it refuses to write a poisoned transcript.
	if err == nil {
		t.Fatal("expected sanitization error on trap-stuffed input, got nil")
	}
	if !strings.Contains(err.Error(), "SANITIZATION FAILURE") {
		t.Fatalf("expected SANITIZATION FAILURE in error, got: %v", err)
	}

	// The output file MUST NOT exist.
	outPath := filepath.Join(transcriptDir, "ID-01-new-actor-benign-onboarding.md")
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Fatal("transcript was written despite sanitization failure — file must not exist")
	}
}

// TestDump_AllEventIDsRendered verifies positive coverage: every event_id from
// the fixture appears in the rendered transcript. Confirms the dumper is not a
// no-op and that all events are included in output.
func TestDump_AllEventIDsRendered(t *testing.T) {
	fixtureDir := t.TempDir()
	transcriptDir := t.TempDir()

	env := cleanEnvelope()
	writeFixtures(t, fixtureDir, env, cleanBaseline())

	resBytes, _ := json.Marshal(cleanResolutionJSON())

	err := run2("ID-01-new-actor-benign-onboarding", fixtureDir, transcriptDir, string(resBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outPath := filepath.Join(transcriptDir, "ID-01-new-actor-benign-onboarding.md")
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("transcript not written: %v", err)
	}

	transcript := string(content)

	// Every event_id in the finding's event_ids must appear in the transcript.
	for _, eid := range env.Finding.EventIDs {
		if !strings.Contains(transcript, eid) {
			t.Errorf("event_id %q not found in transcript", eid)
		}
	}

	// The finding ID itself must also appear.
	if !strings.Contains(transcript, env.Finding.ID) {
		t.Errorf("finding ID %q not found in transcript", env.Finding.ID)
	}
}

// TestDump_StableOrdering runs the dumper twice with identical input and
// verifies the output files are byte-for-byte identical. This protects
// against map iteration order leaking into the rendered transcript.
func TestDump_StableOrdering(t *testing.T) {
	fixtureDir := t.TempDir()
	transcriptDir1 := t.TempDir()
	transcriptDir2 := t.TempDir()

	env := cleanEnvelope()
	writeFixtures(t, fixtureDir, env, cleanBaseline())
	resBytes, _ := json.Marshal(cleanResolutionJSON())

	const sid = "ID-01-new-actor-benign-onboarding"

	if err := run2(sid, fixtureDir, transcriptDir1, string(resBytes)); err != nil {
		t.Fatalf("first run error: %v", err)
	}
	if err := run2(sid, fixtureDir, transcriptDir2, string(resBytes)); err != nil {
		t.Fatalf("second run error: %v", err)
	}

	out1, err := os.ReadFile(filepath.Join(transcriptDir1, sid+".md"))
	if err != nil {
		t.Fatalf("read first output: %v", err)
	}
	out2, err := os.ReadFile(filepath.Join(transcriptDir2, sid+".md"))
	if err != nil {
		t.Fatalf("read second output: %v", err)
	}

	if string(out1) != string(out2) {
		t.Errorf("transcript output is non-deterministic:\n--- run1 ---\n%s\n--- run2 ---\n%s", out1, out2)
	}
}

// run2 is a testable version of run() that accepts arguments directly
// rather than via os.Args / flag.Parse. This allows tests to call the
// core logic without subprocess overhead.
func run2(scenarioID, fixtureDir, transcriptDir, resolutionJSON string) error {
	eventsPath := filepath.Join(fixtureDir, "events.json")
	baselinePath := filepath.Join(fixtureDir, "baseline.json")

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

	rawResolution, err := loadResolutionJSON(resolutionJSON)
	if err != nil {
		return fmt.Errorf("load resolution-json: %w", err)
	}
	var resMap map[string]any
	if err := json.Unmarshal(rawResolution, &resMap); err != nil {
		return fmt.Errorf("parse resolution JSON: %w", err)
	}

	data, err := buildTranscriptData(scenarioID, envelope, bl, resMap)
	if err != nil {
		return fmt.Errorf("build transcript: %w", err)
	}

	buf, err := renderTranscript(data)
	if err != nil {
		return fmt.Errorf("render transcript: %w", err)
	}

	if err := scanForForbidden(buf); err != nil {
		return fmt.Errorf("SANITIZATION FAILURE — refusing to write poisoned transcript: %w", err)
	}

	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		return fmt.Errorf("mkdir transcript-dir: %w", err)
	}
	outPath := filepath.Join(transcriptDir, scenarioID+".md")
	if err := os.WriteFile(outPath, []byte(buf), 0o644); err != nil {
		return fmt.Errorf("write transcript: %w", err)
	}
	return nil
}
