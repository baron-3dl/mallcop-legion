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
	Confidence: 0.95,
	Actor:      "charlie",
	Severity:   "high",
	Source:     "detector:unusual-login",
	Timestamp:  time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
}

func TestFormat(t *testing.T) {
	subject, body := format(sampleResolution)

	subjectCases := []string{"BLOCK", "finding-abc123"}
	for _, want := range subjectCases {
		if !strings.Contains(subject, want) {
			t.Errorf("subject missing %q\ngot: %s", want, subject)
		}
	}

	bodyCases := []string{
		"BLOCK",
		"finding-abc123",
		"charlie",
		"high",
		"detector:unusual-login",
		"login from unknown geo",
		"95%",
		"2026-04-10T09:00:00Z",
	}
	for _, want := range bodyCases {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\ngot:\n%s", want, body)
		}
	}
}

func TestFormat_EmptyOptionals(t *testing.T) {
	res := resolution.Resolution{
		FindingID: "finding-xyz",
		Action:    "alert",
	}
	_, body := format(res)
	if !strings.Contains(body, "ALERT") {
		t.Errorf("expected ALERT in body, got: %s", body)
	}
	if strings.Contains(body, "Actor:") {
		t.Errorf("unexpected Actor: in body with empty actor")
	}
}

func TestConfigFromEnv_MissingHost(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_TO", "to@example.com")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SMTP_HOST")
	}
	if !strings.Contains(err.Error(), "SMTP_HOST") {
		t.Errorf("error should mention SMTP_HOST, got: %v", err)
	}
}

func TestConfigFromEnv_MissingPort(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_TO", "to@example.com")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SMTP_PORT")
	}
	if !strings.Contains(err.Error(), "SMTP_PORT") {
		t.Errorf("error should mention SMTP_PORT, got: %v", err)
	}
}

func TestConfigFromEnv_MissingFrom(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("SMTP_FROM", "")
	t.Setenv("SMTP_TO", "to@example.com")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SMTP_FROM")
	}
	if !strings.Contains(err.Error(), "SMTP_FROM") {
		t.Errorf("error should mention SMTP_FROM, got: %v", err)
	}
}

func TestConfigFromEnv_MissingTo(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_TO", "")

	_, err := configFromEnv()
	if err == nil {
		t.Fatal("expected error for missing SMTP_TO")
	}
	if !strings.Contains(err.Error(), "SMTP_TO") {
		t.Errorf("error should mention SMTP_TO, got: %v", err)
	}
}

func TestConfigFromEnv_AllPresent(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_TO", "to@example.com")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SMTPHost != "localhost" {
		t.Errorf("wrong host: %s", cfg.SMTPHost)
	}
}
