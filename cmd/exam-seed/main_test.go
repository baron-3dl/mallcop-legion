package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// requireCF skips the test if cf is not on PATH.
func requireCF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping campfire integration tests")
	}
	return p
}

// newIsolatedCampfire initialises a fresh cf home in t.TempDir() and creates a
// campfire. Returns (cfHome, campfireID).
func newIsolatedCampfire(t *testing.T, cfBin string) (string, string) {
	t.Helper()

	cfHome := t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	initCmd := exec.Command(cfBin, "init")
	initCmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	createCmd := exec.Command(cfBin, "create", "--description", "test-exam-seed-"+t.Name())
	createCmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := createCmd.Output()
	if err != nil {
		t.Fatalf("cf create: %v\n%s", err, out)
	}

	campfireID := ""
	for _, line := range splitLines(string(out)) {
		if len(line) == 64 && isHex(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from cf create output:\n%s", out)
	}
	return cfHome, campfireID
}

// senderForTest returns a cfSender pointing at cfHome.
func senderForTest(cfBin, cfHome string) *cfSender {
	return &cfSender{cfBin: cfBin, cfHome: cfHome}
}

// readAllMessages reads all messages from the campfire using cf read --all --json.
func readAllMessages(t *testing.T, cfBin, cfHome, campfireID string) []cfMessage {
	t.Helper()

	cmd := exec.Command(cfBin, "read", campfireID, "--all", "--json")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cf read: %v", err)
	}

	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}

	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		t.Fatalf("parse cf read output: %v\nraw: %s", err, out)
	}
	return msgs
}

// repoRoot returns the absolute path to the repo root by walking up from this file.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// cmd/exam-seed/main_test.go → ../.. → repo root
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestSeed_FullCorpus_NoTrapLeak seeds the full 57-scenario corpus into a real
// local campfire and asserts that no ground-truth trap fields appear in any
// emitted message.
func TestSeed_FullCorpus_NoTrapLeak(t *testing.T) {
	cfBin := requireCF(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)
	sender := senderForTest(cfBin, cfHome)

	root := repoRoot(t)
	scenariosDir := filepath.Join(root, "exams", "scenarios")
	fixturesDir := t.TempDir()

	if err := seed(sender, "corpus-test", campfireID, scenariosDir, fixturesDir, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	msgs := readAllMessages(t, cfBin, cfHome, campfireID)

	forbidden := []string{
		"trap_description",
		"trap_resolved_means",
		"expected_resolution",
		"TrapDescription",
		"TrapResolvedMeans",
		"ExpectedResolution",
	}

	for i, msg := range msgs {
		body := []byte(msg.Payload)
		for _, f := range forbidden {
			if bytes.Contains(body, []byte(f)) {
				t.Errorf("message[%d] (id=%s tags=%v) contains forbidden field %q in payload:\n%s",
					i, msg.ID, msg.Tags, f, msg.Payload)
			}
		}
	}

	t.Logf("checked %d messages for trap leaks — all clean", len(msgs))
}

// TestSeed_ReportItemAntecedents seeds the corpus and verifies the exam:report
// message has antecedents equal to the scenario message IDs.
func TestSeed_ReportItemAntecedents(t *testing.T) {
	cfBin := requireCF(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)
	sender := senderForTest(cfBin, cfHome)

	root := repoRoot(t)
	scenariosDir := filepath.Join(root, "exams", "scenarios")
	fixturesDir := t.TempDir()

	if err := seed(sender, "antecedent-test", campfireID, scenariosDir, fixturesDir, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	msgs := readAllMessages(t, cfBin, cfHome, campfireID)

	// Collect scenario message IDs and find the report message.
	scenarioMsgIDs := map[string]bool{}
	var reportMsg *cfMessage

	for i := range msgs {
		msg := &msgs[i]
		if hasTag(msg.Tags, "exam:report") {
			if reportMsg != nil {
				t.Fatal("found more than one exam:report message")
			}
			reportMsg = msg
		} else if hasTag(msg.Tags, "exam:scenario") {
			scenarioMsgIDs[msg.ID] = true
		}
	}

	if reportMsg == nil {
		t.Fatal("no exam:report message found")
	}

	// The number of scenario messages must match.
	if len(reportMsg.Antecedents) != len(scenarioMsgIDs) {
		t.Errorf("report antecedents: got %d want %d", len(reportMsg.Antecedents), len(scenarioMsgIDs))
	}

	// Every antecedent must be a scenario message ID.
	for _, ant := range reportMsg.Antecedents {
		if !scenarioMsgIDs[ant] {
			t.Errorf("report antecedent %q is not a scenario message ID", ant)
		}
	}

	t.Logf("report has %d antecedents matching %d scenario messages", len(reportMsg.Antecedents), len(scenarioMsgIDs))
}

// TestSeed_ScenarioFilter seeds with --scenario ID-01 and asserts exactly
// 2 messages are emitted (1 scenario + 1 report) and the report has 1 antecedent.
func TestSeed_ScenarioFilter(t *testing.T) {
	cfBin := requireCF(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)
	sender := senderForTest(cfBin, cfHome)

	root := repoRoot(t)
	scenariosDir := filepath.Join(root, "exams", "scenarios")
	fixturesDir := t.TempDir()

	const filterID = "ID-01-new-actor-benign-onboarding"
	if err := seed(sender, "filter-test", campfireID, scenariosDir, fixturesDir, filterID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	msgs := readAllMessages(t, cfBin, cfHome, campfireID)

	// Filter to work:create messages only — cf also emits a convention:operation
	// system message when the campfire is first created.
	var workMsgs []cfMessage
	for _, m := range msgs {
		if hasTag(m.Tags, "work:create") {
			workMsgs = append(workMsgs, m)
		}
	}

	if len(workMsgs) != 2 {
		t.Errorf("got %d work:create messages, want 2 (1 scenario + 1 report)", len(workMsgs))
	}

	var reportMsg *cfMessage
	for i := range workMsgs {
		if hasTag(workMsgs[i].Tags, "exam:report") {
			reportMsg = &workMsgs[i]
		}
	}

	if reportMsg == nil {
		t.Fatal("no exam:report message found")
	}
	if len(reportMsg.Antecedents) != 1 {
		t.Errorf("report antecedents: got %d want 1", len(reportMsg.Antecedents))
	}
}

// TestSeed_FixtureContents seeds one scenario and verifies fixture file contents.
func TestSeed_FixtureContents(t *testing.T) {
	root := repoRoot(t)
	scenariosDir := filepath.Join(root, "exams", "scenarios")
	fixturesDir := t.TempDir()

	// Use a mock sender so this test doesn't require cf.
	mock := &mockSender{}

	const filterID = "VA-01-deploy-burst"
	if err := seed(mock, "fixture-test", "fake-cf-id", scenariosDir, fixturesDir, filterID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Load the original scenario to compare counts.
	scenarioPath := filepath.Join(root, "exams", "scenarios", "behavioral", "VA-01-deploy-burst.yaml")
	s, err := loadScenarios(scenariosDir, filterID)
	if err != nil || len(s) == 0 {
		// Fall back to direct load if loadScenarios fails.
		_ = scenarioPath
		t.Fatalf("loadScenarios: %v", err)
	}
	scenario := s[0]

	fixDir := filepath.Join(fixturesDir, "fixture-test", filterID)

	// Check events.json.
	eventsPath := filepath.Join(fixDir, "events.json")
	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events.json: %v", err)
	}
	var evts fixtureEvents
	if err := json.Unmarshal(eventsData, &evts); err != nil {
		t.Fatalf("unmarshal events.json: %v", err)
	}
	if len(evts.Events) != len(scenario.Events) {
		t.Errorf("events.json count: got %d want %d", len(evts.Events), len(scenario.Events))
	}

	// Check baseline.json.
	baselinePath := filepath.Join(fixDir, "baseline.json")
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline.json: %v", err)
	}
	var bl fixtureBaseline
	if err := json.Unmarshal(baselineData, &bl); err != nil {
		t.Fatalf("unmarshal baseline.json: %v", err)
	}

	if scenario.Baseline != nil {
		wantActors := scenario.Baseline.KnownEntities.Actors
		if len(bl.KnownEntities.Actors) != len(wantActors) {
			t.Errorf("baseline known_entities.actors: got %d want %d",
				len(bl.KnownEntities.Actors), len(wantActors))
		}
	}
}

// mockSender implements ReadySender for unit tests that don't need cf.
type mockSender struct {
	calls []mockCall
	nextID int
}

type mockCall struct {
	CampfireID  string
	Payload     string
	Tags        []string
	Antecedents []string
	ReturnedID  string
}

func (m *mockSender) SendWithAntecedents(campfireID, payload string, tags []string, antecedents []string) (string, error) {
	m.nextID++
	id := "mock-msg-" + itoa(m.nextID)
	m.calls = append(m.calls, mockCall{
		CampfireID:  campfireID,
		Payload:     payload,
		Tags:        tags,
		Antecedents: antecedents,
		ReturnedID:  id,
	})
	return id, nil
}

// --- helpers ---

func hasTag(tags []string, t string) bool {
	for _, tag := range tags {
		if tag == t {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, trimSpaceStr(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, trimSpaceStr(s[start:]))
	}
	return lines
}

func trimSpaceStr(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
