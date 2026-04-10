package main

import (
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

var sampleResolution = resolution.Resolution{
	FindingID:  "finding-abc123",
	Action:     "block",
	Reason:     "login from unknown geo",
	Confidence: 0.85,
	Actor:      "charlie",
	Severity:   "high",
	Source:     "detector:unusual-login",
	Timestamp:  time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
}

func TestFormat(t *testing.T) {
	msg := format(sampleResolution)

	cases := []string{
		"BLOCK",
		"finding-abc123",
		"charlie",
		"high",
		"detector:unusual-login",
		"login from unknown geo",
		"85%",
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
		Action:    "alert",
	}
	msg := format(res)
	if !strings.Contains(msg, "ALERT") {
		t.Errorf("expected ALERT in message, got: %s", msg)
	}
	if strings.Contains(msg, "Actor:") {
		t.Errorf("unexpected Actor: in message with empty actor")
	}
}

func TestConfigFromEnv_MissingURL(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SLACK_WEBHOOK_URL")
	}
	if !strings.Contains(err.Error(), "SLACK_WEBHOOK_URL") {
		t.Errorf("error should mention SLACK_WEBHOOK_URL, got: %v", err)
	}
}

func TestConfigFromEnv_Present(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/fake")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WebhookURL != "https://hooks.slack.com/services/fake" {
		t.Errorf("wrong webhook URL: %s", cfg.WebhookURL)
	}
}
