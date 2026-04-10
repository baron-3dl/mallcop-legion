package main

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{}

func makeGitEvent(id, actor, evType, ref string, forced, deleted bool, commitMsg string) event.Event {
	payload, _ := json.Marshal(map[string]interface{}{
		"forced":         forced,
		"deleted":        deleted,
		"ref":            ref,
		"commit_message": commitMsg,
	})
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   payload,
	}
}

func TestEvaluate_NormalPush(t *testing.T) {
	ev := makeGitEvent("evt-a", "alice", "push", "refs/heads/feature-x", false, false, "add feature x")
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for normal push, got %d", len(findings))
	}
}

func TestEvaluate_ForcePushNonProtected(t *testing.T) {
	ev := makeGitEvent("evt-b", "alice", "push", "refs/heads/feature-x", true, false, "")
	findings := evaluate(ev, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for force push, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
	if f.Type != "git-oops" {
		t.Errorf("type: got %q want git-oops", f.Type)
	}
}

func TestEvaluate_ForcePushMain(t *testing.T) {
	ev := makeGitEvent("evt-c", "alice", "push", "refs/heads/main", true, false, "")
	findings := evaluate(ev, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
}

func TestEvaluate_BranchDelete(t *testing.T) {
	ev := makeGitEvent("evt-d", "bob", "push", "refs/heads/old-branch", false, true, "")
	findings := evaluate(ev, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for branch delete, got %d", len(findings))
	}
	if findings[0].Severity != "medium" {
		t.Errorf("severity: got %q want medium", findings[0].Severity)
	}
}

func TestEvaluate_ForcePushAndDelete(t *testing.T) {
	ev := makeGitEvent("evt-e", "bob", "push", "refs/heads/feature-y", true, true, "")
	findings := evaluate(ev, testBaseline)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (force+delete), got %d", len(findings))
	}
}

func TestEvaluate_SecretInCommitMessage_GitHubPAT(t *testing.T) {
	msg := "fix auth ghp_abcdefghijklmnopqrstuvwxyz1234567890 token"
	ev := makeGitEvent("evt-f", "carol", "push", "refs/heads/main", false, false, msg)
	findings := evaluate(ev, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for GitHub PAT in commit msg, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
}

func TestEvaluate_SecretInCommitMessage_AWSKey(t *testing.T) {
	msg := "deploy: AKIAIOSFODNN7EXAMPLE"
	ev := makeGitEvent("evt-g", "carol", "push", "refs/heads/main", false, false, msg)
	findings := evaluate(ev, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for AWS key in commit msg, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
}

func TestEvaluate_NonGitSource(t *testing.T) {
	ev := event.Event{
		ID: "evt-h", Source: "aws", Type: "push", Actor: "alice",
		Timestamp: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
	}
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-git source, got %d", len(findings))
	}
}

func TestGoldenFixture(t *testing.T) {
	bl, err := baseline.Load("testdata/baseline.json")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	eventsFile, err := os.Open("testdata/events.jsonl")
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer eventsFile.Close()

	goldenFile, err := os.Open("testdata/findings.golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer goldenFile.Close()

	var got []finding.Finding
	scanner := bufio.NewScanner(eventsFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		got = append(got, evaluate(ev, bl)...)
	}

	var want []finding.Finding
	gScanner := bufio.NewScanner(goldenFile)
	for gScanner.Scan() {
		line := gScanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("unmarshal golden finding: %v", err)
		}
		want = append(want, f)
	}

	if len(got) != len(want) {
		t.Fatalf("finding count: got %d want %d\ngot: %+v\nwant: %+v", len(got), len(want), got, want)
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID {
			t.Errorf("[%d] ID: got %q want %q", i, g.ID, w.ID)
		}
		if g.Severity != w.Severity {
			t.Errorf("[%d] Severity: got %q want %q", i, g.Severity, w.Severity)
		}
		if g.Type != w.Type {
			t.Errorf("[%d] Type: got %q want %q", i, g.Type, w.Type)
		}
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
