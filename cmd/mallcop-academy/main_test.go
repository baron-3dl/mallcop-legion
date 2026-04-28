// Tests for mallcop-academy.
//
// Unit tests cover:
//   - findingTrackingID determinism
//   - payload composition (sanitized finding shape)
//   - watch-loop classification (terminal vs intermediate actions)
//   - per-scenario JSON record writing
//
// Integration tests use real isolated campfires (cf init + cf create) to verify:
//   - work:create message posted with correct tags
//   - synthetic work:close classified as terminal
//   - per-scenario JSON artifact written
//
// No cf primitives are mocked. All campfire interaction uses real cf binary
// calls against isolated campfire instances in t.TempDir().
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// ---- unit: findingTrackingID --------------------------------------------------

func TestFindingTrackingID_Deterministic(t *testing.T) {
	id1 := findingTrackingID("run-001", "AC-01")
	id2 := findingTrackingID("run-001", "AC-01")
	if id1 != id2 {
		t.Errorf("findingTrackingID not deterministic: %q vs %q", id1, id2)
	}
	// Must embed run-id and scenario-id.
	if !strings.Contains(id1, "run-001") {
		t.Errorf("findingTrackingID %q does not contain run-id", id1)
	}
	if !strings.Contains(id1, "AC-01") {
		t.Errorf("findingTrackingID %q does not contain scenario-id", id1)
	}
}

func TestFindingTrackingID_DifferentInputsDifferentOutputs(t *testing.T) {
	a := findingTrackingID("run-001", "AC-01")
	b := findingTrackingID("run-001", "AC-02")
	c := findingTrackingID("run-002", "AC-01")
	if a == b {
		t.Errorf("different scenario IDs produced same tracking ID: %q", a)
	}
	if a == c {
		t.Errorf("different run IDs produced same tracking ID: %q", a)
	}
}

// ---- unit: payload composition -----------------------------------------------

func TestPayloadComposition_FindingFields(t *testing.T) {
	s := &exam.Scenario{
		ID: "AC-01",
		Finding: &exam.ScenarioFinding{
			ID:       "fnd_ac_001",
			Detector: "detector-unusual-login",
			Title:    "Unusual login from new actor",
			Severity: "medium",
			EventIDs: []string{"evt-001", "evt-002"},
			Metadata: exam.FindingMetadata{"actor": "deploy-svc-new"},
		},
		ExpectedResolution: &exam.ExpectedResolution{
			ChainAction: "escalated",
		},
	}

	// Build payload the same way postFinding does.
	runID := "test-run"
	fid := findingTrackingID(runID, s.ID)
	fp := findingPayload{
		ID:       s.Finding.ID,
		Detector: s.Finding.Detector,
		Title:    s.Finding.Title,
		Severity: s.Finding.Severity,
		EventIDs: s.Finding.EventIDs,
		Metadata: filterAcademyMetadata(s.Finding.Metadata),
	}
	payload := academyFindingPayload{
		ID:      fid,
		Title:   s.Finding.Title,
		Skill:   "task:triage",
		Finding: fp,
		AcademyMetadata: academyMetadata{
			ScenarioID: s.ID,
			RunID:      runID,
			Expected:   s.ExpectedResolution,
		},
	}

	// ID must be the tracking ID.
	if payload.ID != fid {
		t.Errorf("payload.ID = %q, want %q", payload.ID, fid)
	}
	// Skill must be task:triage.
	if payload.Skill != "task:triage" {
		t.Errorf("payload.Skill = %q, want task:triage", payload.Skill)
	}
	// Finding must carry original fields.
	if payload.Finding.Detector != "detector-unusual-login" {
		t.Errorf("finding.Detector = %q, want detector-unusual-login", payload.Finding.Detector)
	}
	if len(payload.Finding.EventIDs) != 2 {
		t.Errorf("finding.EventIDs len = %d, want 2", len(payload.Finding.EventIDs))
	}
	// AcademyMetadata must carry scenario_id, run_id, expected.
	if payload.AcademyMetadata.ScenarioID != "AC-01" {
		t.Errorf("academy_metadata.scenario_id = %q, want AC-01", payload.AcademyMetadata.ScenarioID)
	}
	if payload.AcademyMetadata.Expected == nil {
		t.Error("academy_metadata.expected must not be nil")
	} else if payload.AcademyMetadata.Expected.ChainAction != "escalated" {
		t.Errorf("expected.chain_action = %q, want escalated", payload.AcademyMetadata.Expected.ChainAction)
	}

	// Must marshal cleanly.
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if len(b) == 0 {
		t.Error("marshalled payload is empty")
	}
}

// ---- unit: terminal action classification ------------------------------------

func TestTerminalActions_KnownValues(t *testing.T) {
	terminal := []string{"resolved", "escalated", "remediated", "false-positive", "closed"}
	for _, a := range terminal {
		if !terminalActions[a] {
			t.Errorf("action %q should be terminal", a)
		}
	}
}

func TestTerminalActions_IntermediateNotTerminal(t *testing.T) {
	intermediate := []string{"created", "updated", "in-progress", "work:create", ""}
	for _, a := range intermediate {
		if terminalActions[a] {
			t.Errorf("action %q should not be terminal", a)
		}
	}
}

// ---- unit: hasTag helper ------------------------------------------------------

func TestHasTag(t *testing.T) {
	tags := []string{"work:close", "action:resolved", "run:abc"}
	if !hasTag(tags, "work:close") {
		t.Error("hasTag: should find work:close")
	}
	if hasTag(tags, "work:create") {
		t.Error("hasTag: should not find work:create")
	}
	if hasTag(nil, "any") {
		t.Error("hasTag: nil tags should return false")
	}
}

// ---- unit: scenario record writing -------------------------------------------

func TestWriteScenarioRecord_Terminal(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()
	termAt := now.Add(5 * time.Second)

	ts := &trackedScenario{
		scenarioID:     "AC-01",
		findingID:      "academy-run-001-AC-01",
		workItemID:     "msg-abc123",
		postedAt:       now,
		chain:          []ChainEntry{{ItemID: "msg-abc123", Skill: "task:triage"}, {ItemID: "item-xyz", Action: "resolved"}},
		terminal:       true,
		terminalAt:     termAt,
		terminalAction: "resolved",
		terminalItemID: "item-xyz",
	}

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	recordPath := filepath.Join(outDir, "AC-01.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}

	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}
	if rec.ScenarioID != "AC-01" {
		t.Errorf("scenario_id = %q, want AC-01", rec.ScenarioID)
	}
	if rec.FindingID != "academy-run-001-AC-01" {
		t.Errorf("finding_id = %q, want academy-run-001-AC-01", rec.FindingID)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalItemID != "item-xyz" {
		t.Errorf("terminal_item_id = %q, want item-xyz", rec.TerminalItemID)
	}
	if rec.WallSeconds <= 0 {
		t.Errorf("wall_seconds = %f, want > 0", rec.WallSeconds)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must be non-nil for terminal scenario")
	}
	if len(rec.FullChain) != 2 {
		t.Errorf("full_chain len = %d, want 2", len(rec.FullChain))
	}
}

func TestWriteScenarioRecord_NonTerminal(t *testing.T) {
	outDir := t.TempDir()
	now := time.Now()

	ts := &trackedScenario{
		scenarioID: "AC-02",
		findingID:  "academy-run-001-AC-02",
		workItemID: "msg-def456",
		postedAt:   now,
		chain:      []ChainEntry{{ItemID: "msg-def456", Skill: "task:triage"}},
	}

	if err := writeScenarioRecord(ts, "run-001", "cf-abc", outDir); err != nil {
		t.Fatalf("writeScenarioRecord: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.TerminalAt != nil {
		t.Error("terminal_at should be nil for non-terminal scenario")
	}
	if rec.TerminalAction != "" {
		t.Errorf("terminal_action should be empty, got %q", rec.TerminalAction)
	}
}

// ---- unit: run.json writing ---------------------------------------------------

func TestWriteRunJSON(t *testing.T) {
	outDir := t.TempDir()
	rec := RunRecord{
		RunID:          "acad-12345",
		TargetCampfire: "cf-abc",
		ScenariosDir:   "/some/dir",
		JudgeModel:     "claude-haiku-4-5",
		BudgetUSD:      10.0,
		MaxConcurrent:  4,
		Timeout:        "30m",
		StartedAt:      time.Now(),
	}
	if err := writeJSON(filepath.Join(outDir, "run.json"), rec); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var parsed RunRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if parsed.RunID != "acad-12345" {
		t.Errorf("run_id = %q, want acad-12345", parsed.RunID)
	}
	if parsed.JudgeModel != "claude-haiku-4-5" {
		t.Errorf("judge_model = %q, want claude-haiku-4-5", parsed.JudgeModel)
	}
}

// ---- mock Sender for unit tests ----------------------------------------------

// mockSender records calls without touching a real campfire.
type mockSender struct {
	mu       sync.Mutex
	sends    []mockSendCall
	readMsgs []cfMessage
	nextID   int
}

type mockSendCall struct {
	campfireID string
	payload    string
	tags       []string
	returnID   string
}

func (m *mockSender) send(campfireID, payload string, tags []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := fmt.Sprintf("mock-msg-%d", m.nextID)
	m.sends = append(m.sends, mockSendCall{campfireID: campfireID, payload: payload, tags: tags, returnID: id})
	return id, nil
}

func (m *mockSender) readAll(campfireID string) ([]cfMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]cfMessage, len(m.readMsgs))
	copy(out, m.readMsgs)
	return out, nil
}

// ---- unit: academy with mock sender ------------------------------------------

func TestAcademyMock_PostsWorkCreate(t *testing.T) {
	// Build a minimal scenario YAML in a temp dir.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-01", "fnd_ac_001", "detector-new-actor",
		"New actor observed: deploy-svc-new", "medium")

	outDir := t.TempDir()
	ms := &mockSender{
		readMsgs: []cfMessage{
			// Simulate a work:close terminal message that arrives after posting.
			// The close references the work:create message ID which we'll fill in.
		},
	}

	// We'll do a short-timeout run; mock sender returns no close messages → timeout.
	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "AC-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        100 * time.Millisecond, // very short for mock test
		runID:          "test-mock-run",
	}

	err := academy(ms, args)
	if err != nil {
		t.Fatalf("academy: %v", err)
	}

	// One work:create must have been sent.
	ms.mu.Lock()
	nSends := len(ms.sends)
	ms.mu.Unlock()
	if nSends != 1 {
		t.Errorf("expected 1 work:create send, got %d", nSends)
	}

	ms.mu.Lock()
	call := ms.sends[0]
	ms.mu.Unlock()

	if call.campfireID != "cf-mock-target" {
		t.Errorf("send campfireID = %q, want cf-mock-target", call.campfireID)
	}
	if !contains(call.tags, "work:create") {
		t.Errorf("send tags missing work:create; got %v", call.tags)
	}
	if !contains(call.tags, "task:triage") {
		t.Errorf("send tags missing task:triage; got %v", call.tags)
	}
	if !contains(call.tags, "academy:scenario") {
		t.Errorf("send tags missing academy:scenario; got %v", call.tags)
	}

	// Payload must be valid JSON with skill=task:triage.
	var p academyFindingPayload
	if err := json.Unmarshal([]byte(call.payload), &p); err != nil {
		t.Fatalf("parse send payload: %v", err)
	}
	if p.Skill != "task:triage" {
		t.Errorf("payload.skill = %q, want task:triage", p.Skill)
	}
	if p.AcademyMetadata.ScenarioID != "AC-01" {
		t.Errorf("academy_metadata.scenario_id = %q, want AC-01", p.AcademyMetadata.ScenarioID)
	}

	// run.json must exist.
	if _, err := os.Stat(filepath.Join(outDir, "run.json")); err != nil {
		t.Errorf("run.json not found: %v", err)
	}
	// Partial scenario record written (non-terminal because mock returned no closes).
	if _, err := os.Stat(filepath.Join(outDir, "AC-01.json")); err != nil {
		t.Errorf("AC-01.json not found: %v", err)
	}
}

func TestAcademyMock_TerminalCloseWritesRecord(t *testing.T) {
	// Build a minimal scenario YAML.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-02", "fnd_ac_002", "detector-priv-escalation",
		"Privilege escalation detected", "high")

	outDir := t.TempDir()

	// Mock sender that returns a close message after we know the send ID.
	ms := &mockSender{readMsgs: nil}

	args := runArgs{
		targetCampfire: "cf-mock-target",
		scenariosDir:   scenDir,
		scenarioFilter: "AC-02",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        5 * time.Second,
		runID:          "test-mock-run-2",
	}

	// Run academy in a goroutine; once we see the send, inject the close message.
	done := make(chan error, 1)
	go func() {
		done <- academy(ms, args)
	}()

	// Wait until the work:create is sent, then inject the terminal close.
	var sentID string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		ms.mu.Lock()
		if len(ms.sends) > 0 {
			sentID = ms.sends[0].returnID
		}
		ms.mu.Unlock()
		if sentID != "" {
			break
		}
	}
	if sentID == "" {
		t.Fatal("academy never posted work:create within timeout")
	}

	// Inject a terminal work:close message.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	ms.mu.Lock()
	ms.readMsgs = append(ms.readMsgs, cfMessage{
		ID:      "close-msg-001",
		Tags:    []string{"work:close", "action:resolved"},
		Payload: string(closePayloadBytes),
	})
	ms.mu.Unlock()

	// Wait for academy to finish.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("academy did not complete within deadline")
	}

	// AC-02.json must exist and be terminal.
	data, err := os.ReadFile(filepath.Join(outDir, "AC-02.json"))
	if err != nil {
		t.Fatalf("AC-02.json not found: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse AC-02.json: %v", err)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil")
	}
}

// ---- integration: real isolated campfire -------------------------------------

// requireCF skips the test if the cf binary is not on PATH.
func requireCF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping real campfire integration tests")
	}
	return p
}

// newIsolatedCampfire creates a fresh CF_HOME + campfire in a temp dir.
func newIsolatedCampfire(t *testing.T, cfBin string) (cfHome, campfireID string) {
	t.Helper()
	cfHome = t.TempDir()

	// cf init
	cmd := exec.Command(cfBin, "init")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	// cf create
	cmd = exec.Command(cfBin, "create", "--description", "academy-test-"+t.Name())
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cf create: %v\n%s", err, out)
	}

	// Extract 64-char hex ID from output.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 64 && isHex(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from: %s", out)
	}
	return cfHome, campfireID
}

// cfSendRaw sends a message via cf send and returns the parsed cfMessage.
func cfSendRaw(t *testing.T, cfBin, cfHome, campfireID, payload string, tags []string) cfMessage {
	t.Helper()
	args := []string{"send", campfireID, payload, "--json"}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	cmd := exec.Command(cfBin, args...)
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cf send: %v\nout: %s", err, out)
	}
	var msg cfMessage
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("parse cf send output: %v\nraw: %s", err, out)
	}
	return msg
}

// cfReadAll reads all messages from the campfire.
func cfReadAll(t *testing.T, cfBin, cfHome, campfireID string) []cfMessage {
	t.Helper()
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all")
	cmd.Env = setEnv(os.Environ(), "CF_HOME", cfHome)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		t.Logf("cf read parse error: %v; raw: %s", err, out)
		return nil
	}
	return msgs
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// TestAcademyIntegration_RealCampfire verifies that academy:
//  1. Posts a work:create to the real campfire with the correct tags.
//  2. Classifies a synthetic work:close as terminal.
//  3. Writes a per-scenario JSON artifact.
func TestAcademyIntegration_RealCampfire(t *testing.T) {
	cfBin := requireCF(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	// Build a minimal scenario YAML.
	scenDir := t.TempDir()
	writeMinimalScenario(t, scenDir, "AC-01", "fnd_ac_001", "detector-new-actor",
		"New actor observed: deploy-svc-new", "medium")

	outDir := t.TempDir()

	// Use a real cfSender pointed at the isolated campfire.
	sender := &cfSender{cfBin: cfBin, cfHome: cfHome}

	args := runArgs{
		targetCampfire: campfireID,
		scenariosDir:   scenDir,
		scenarioFilter: "AC-01",
		outputDir:      outDir,
		maxConcurrent:  1,
		timeout:        10 * time.Second,
		runID:          "integ-test-001",
	}

	done := make(chan error, 1)
	go func() {
		done <- academy(sender, args)
	}()

	// Wait for the work:create to appear in the campfire.
	var sentMsgID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		msgs := cfReadAll(t, cfBin, cfHome, campfireID)
		for _, msg := range msgs {
			if hasTag(msg.Tags, "work:create") {
				sentMsgID = msg.ID
				break
			}
		}
		if sentMsgID != "" {
			break
		}
	}
	if sentMsgID == "" {
		t.Fatal("academy never posted work:create to real campfire within timeout")
	}

	// Verify tags on the work:create message.
	msgs := cfReadAll(t, cfBin, cfHome, campfireID)
	var workCreateMsg *cfMessage
	for i := range msgs {
		if msgs[i].ID == sentMsgID {
			workCreateMsg = &msgs[i]
			break
		}
	}
	if workCreateMsg == nil {
		t.Fatal("could not find work:create message by ID")
	}
	for _, want := range []string{"work:create", "task:triage", "academy:scenario", "scenario:AC-01"} {
		if !hasTag(workCreateMsg.Tags, want) {
			t.Errorf("work:create message missing tag %q; got %v", want, workCreateMsg.Tags)
		}
	}

	// Verify payload is valid JSON with skill=task:triage.
	var p academyFindingPayload
	if err := json.Unmarshal([]byte(workCreateMsg.Payload), &p); err != nil {
		t.Fatalf("parse work:create payload: %v", err)
	}
	if p.Skill != "task:triage" {
		t.Errorf("payload.skill = %q, want task:triage", p.Skill)
	}
	trackingID := findingTrackingID("integ-test-001", "AC-01")
	if p.ID != trackingID {
		t.Errorf("payload.id = %q, want %q", p.ID, trackingID)
	}

	// Post a synthetic work:close referencing the sent message ID.
	closePayloadBytes, _ := json.Marshal(closePayload{
		ItemID: sentMsgID,
		Action: "resolved",
		Skill:  "task:triage",
	})
	cfSendRaw(t, cfBin, cfHome, campfireID, string(closePayloadBytes),
		[]string{"work:close", "action:resolved"})

	// Wait for academy to finish (it should detect terminal close).
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("academy returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("academy did not complete within deadline after terminal close")
	}

	// run.json must exist.
	runJSON := filepath.Join(outDir, "run.json")
	if _, err := os.Stat(runJSON); err != nil {
		t.Errorf("run.json not found: %v", err)
	}
	runData, err := os.ReadFile(runJSON)
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var runRec RunRecord
	if err := json.Unmarshal(runData, &runRec); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if runRec.RunID != "integ-test-001" {
		t.Errorf("run.json run_id = %q, want integ-test-001", runRec.RunID)
	}
	if runRec.TargetCampfire != campfireID {
		t.Errorf("run.json target_campfire = %q, want %q", runRec.TargetCampfire, campfireID)
	}

	// Per-scenario JSON must exist and be terminal.
	scenJSON := filepath.Join(outDir, "AC-01.json")
	if _, err := os.Stat(scenJSON); err != nil {
		t.Errorf("AC-01.json not found: %v", err)
	}
	scenData, err := os.ReadFile(scenJSON)
	if err != nil {
		t.Fatalf("read AC-01.json: %v", err)
	}
	var rec ScenarioRecord
	if err := json.Unmarshal(scenData, &rec); err != nil {
		t.Fatalf("parse AC-01.json: %v", err)
	}
	if rec.ScenarioID != "AC-01" {
		t.Errorf("scenario_id = %q, want AC-01", rec.ScenarioID)
	}
	if rec.TerminalAction != "resolved" {
		t.Errorf("terminal_action = %q, want resolved", rec.TerminalAction)
	}
	if rec.TerminalAt == nil {
		t.Error("terminal_at must not be nil")
	}
	if rec.WallSeconds <= 0 {
		t.Errorf("wall_seconds = %f, want > 0", rec.WallSeconds)
	}
	if len(rec.FullChain) == 0 {
		t.Error("full_chain must not be empty")
	}
}

// ---- helpers -----------------------------------------------------------------

// writeMinimalScenario writes a minimal scenario YAML to dir/<id>.yaml.
// All string fields are quoted to avoid YAML parse issues with spaces/colons.
func writeMinimalScenario(t *testing.T, dir, id, findingID, detector, title, severity string) {
	t.Helper()
	content := fmt.Sprintf(`id: %s
failure_mode: test
detector: %s
category: test
difficulty: easy
finding:
  id: %s
  detector: %s
  title: %q
  severity: %s
  event_ids: [evt-001]
events:
  - id: evt-001
    timestamp: "2026-01-01T00:00:00Z"
    source: github
    event_type: push
    actor: deploy-svc-new
    action: push
    target: repo/main
    severity: medium
baseline:
  known_entities:
    actors: [deploy-svc]
    sources: [github]
expected:
  chain_action: escalated
  triage_action: escalate
`, id, detector, findingID, detector, title, severity)
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write scenario YAML: %v", err)
	}
}

// contains checks if s is in slice.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
