package main

import (
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

var sampleResolution = resolution.Resolution{
	FindingID:  "finding-abc123",
	Action:     "escalate",
	Reason:     "privileged account anomaly",
	Confidence: 0.78,
	Actor:      "svc-deploy",
	Severity:   "critical",
	Source:     "detector:priv-escalation",
	Timestamp:  time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
}

func TestFormat(t *testing.T) {
	msg := format(sampleResolution)

	cases := []string{
		"ESCALATE",
		"finding-abc123",
		"svc-deploy",
		"critical",
		"detector:priv-escalation",
		"privileged account anomaly",
		"78%",
		"2026-04-10T09:00:00Z",
	}
	for _, want := range cases {
		if !strings.Contains(msg, want) {
			t.Errorf("format output missing %q\ngot:\n%s", want, msg)
		}
	}
}

func TestFormat_EmptyOptionals(t *testing.T) {
	res := resolution.Resolution{
		FindingID: "finding-xyz",
		Action:    "ignore",
	}
	msg := format(res)
	if !strings.Contains(msg, "IGNORE") {
		t.Errorf("expected IGNORE in message, got: %s", msg)
	}
	if strings.Contains(msg, "Actor:") {
		t.Errorf("unexpected Actor: in message with empty actor")
	}
}

func TestConfigFromEnv_MissingURL(t *testing.T) {
	t.Setenv("TEAMS_WEBHOOK_URL", "")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing TEAMS_WEBHOOK_URL")
	}
	if !strings.Contains(err.Error(), "TEAMS_WEBHOOK_URL") {
		t.Errorf("error should mention TEAMS_WEBHOOK_URL, got: %v", err)
	}
}

func TestConfigFromEnv_Present(t *testing.T) {
	t.Setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/fake")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WebhookURL != "https://outlook.office.com/webhook/fake" {
		t.Errorf("wrong webhook URL: %s", cfg.WebhookURL)
	}
}
