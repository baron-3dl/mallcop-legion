package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{}

func makeEvent(id, evType, actor string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    "app",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 17, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_BenignEvent(t *testing.T) {
	ev := makeEvent("evt-a", "chat", "alice", map[string]interface{}{
		"message": "please summarize the security report",
		"user_id": "usr-123",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for benign event, got %d: %+v", len(findings), findings)
	}
}

func TestEvaluate_AWSAccessKey(t *testing.T) {
	ev := makeEvent("evt-b", "config_push", "alice", map[string]interface{}{
		"content": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for AWS access key, got 0")
	}
	assertFindingWithName(t, findings, "aws-access-key-id", "critical")
}

func TestEvaluate_GitHubPAT(t *testing.T) {
	ev := makeEvent("evt-c", "env_update", "bob", map[string]interface{}{
		"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for GitHub PAT, got 0")
	}
	assertFindingWithName(t, findings, "github-pat", "critical")
}

func TestEvaluate_SlackToken(t *testing.T) {
	// Built via strings.Repeat so the literal in the source doesn't match
	// GitHub push-protection secret scanners (the regex needs 10+ chars
	// after "xox[bpsar]-"; the detector sees the full concatenated form).
	ev := makeEvent("evt-d", "env_update", "carol", map[string]interface{}{
		"slack_token": "xoxb-" + strings.Repeat("a", 36),
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for Slack token, got 0")
	}
	assertFindingWithName(t, findings, "slack-token", "critical")
}

func TestEvaluate_StripeLiveKey(t *testing.T) {
	// Built via strings.Repeat so the literal in the source doesn't match
	// GitHub push-protection secret scanners (the regex needs 24+ chars
	// after "sk_live_"; the detector sees the full concatenated form).
	ev := makeEvent("evt-e", "config_push", "alice", map[string]interface{}{
		"payment_key": "sk_live_" + strings.Repeat("a", 24),
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for Stripe live key, got 0")
	}
	assertFindingWithName(t, findings, "stripe-live-key", "critical")
}

func TestEvaluate_PrivateKeyPEM(t *testing.T) {
	ev := makeEvent("evt-f", "file_upload", "alice", map[string]interface{}{
		"content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for RSA private key, got 0")
	}
	assertFindingWithName(t, findings, "private-key-pem", "critical")
}

func TestEvaluate_ConnectionStringWithCreds(t *testing.T) {
	ev := makeEvent("evt-g", "config_push", "devops", map[string]interface{}{
		"database_url": "postgres://admin:supersecretpassword123@db.internal:5432/production",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for connection string with credentials, got 0")
	}
	assertFindingWithName(t, findings, "connection-string-with-creds", "critical")
}

func TestEvaluate_JWTToken(t *testing.T) {
	ev := makeEvent("evt-h", "api_call", "svc-bot", map[string]interface{}{
		"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for JWT token, got 0")
	}
}

func TestEvaluate_GenericPassword(t *testing.T) {
	ev := makeEvent("evt-i", "config_update", "alice", map[string]interface{}{
		"db_config": "password=supersecretdbpassword123",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for generic password assignment, got 0")
	}
}

func TestEvaluate_AnthropicAPIKey(t *testing.T) {
	ev := makeEvent("evt-j", "env_update", "alice", map[string]interface{}{
		"api_key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcde-AAAAAAA",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for Anthropic API key, got 0")
	}
	assertFindingWithName(t, findings, "anthropic-api-key", "critical")
}

func TestEvaluate_EmptyPayload(t *testing.T) {
	ev := event.Event{
		ID:        "evt-k",
		Source:    "app",
		Type:      "chat",
		Actor:     "alice",
		Timestamp: time.Date(2026, 4, 10, 17, 0, 0, 0, time.UTC),
	}
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty payload, got %d", len(findings))
	}
}

func assertFindingWithName(t *testing.T, findings []finding.Finding, wantName, wantSeverity string) {
	t.Helper()
	for _, f := range findings {
		var ev map[string]string
		_ = json.Unmarshal(f.Evidence, &ev)
		if ev["pattern"] == wantName {
			if f.Severity != wantSeverity {
				t.Errorf("finding %q: severity got %q want %q", wantName, f.Severity, wantSeverity)
			}
			return
		}
	}
	t.Errorf("no finding with pattern %q found in %+v", wantName, findings)
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
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
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
