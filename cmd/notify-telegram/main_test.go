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
	Confidence: 0.92,
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
		"92%",
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

func TestConfigFromEnv_MissingToken(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "12345")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing TELEGRAM_BOT_TOKEN")
	}
	if !strings.Contains(err.Error(), "TELEGRAM_BOT_TOKEN") {
		t.Errorf("error should mention TELEGRAM_BOT_TOKEN, got: %v", err)
	}
}

func TestConfigFromEnv_MissingChatID(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "fake-token")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing TELEGRAM_CHAT_ID")
	}
	if !strings.Contains(err.Error(), "TELEGRAM_CHAT_ID") {
		t.Errorf("error should mention TELEGRAM_CHAT_ID, got: %v", err)
	}
}

func TestConfigFromEnv_AllPresent(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "fake-token")
	t.Setenv("TELEGRAM_CHAT_ID", "99999")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Token != "fake-token" {
		t.Errorf("wrong token: %s", cfg.Token)
	}
	if cfg.ChatID != "99999" {
		t.Errorf("wrong chat_id: %s", cfg.ChatID)
	}
}
