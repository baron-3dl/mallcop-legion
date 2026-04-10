//go:build integration

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

func TestIntegration_Email(t *testing.T) {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	from := os.Getenv("SMTP_FROM")
	to := os.Getenv("SMTP_TO")
	if host == "" || port == "" || from == "" || to == "" {
		t.Skip("SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TO required for integration test")
	}

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("config error: %v", err)
	}

	res := resolution.Resolution{
		FindingID:  "integration-test-finding",
		Action:     "alert",
		Reason:     "[TEST] integration test from notify-email",
		Confidence: 1.0,
		Actor:      "test-actor",
		Severity:   "low",
		Source:     "notify-email-integration-test",
		Timestamp:  time.Now().UTC(),
	}
	subject, body := format(res)
	subject = "[TEST] " + subject

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := send(ctx, cfg, subject, body); err != nil {
		t.Fatalf("send failed: %v", err)
	}
}
