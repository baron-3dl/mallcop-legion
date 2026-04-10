//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

func TestIntegration_Teams(t *testing.T) {
	webhookURL := os.Getenv("TEAMS_WEBHOOK_URL")
	if webhookURL == "" {
		t.Skip("TEAMS_WEBHOOK_URL required for integration test")
	}

	res := resolution.Resolution{
		FindingID:  "integration-test-finding",
		Action:     "alert",
		Reason:     "[TEST] integration test from notify-teams",
		Confidence: 1.0,
		Actor:      "test-actor",
		Severity:   "low",
		Source:     "notify-teams-integration-test",
		Timestamp:  time.Now().UTC(),
	}
	msg := fmt.Sprintf("[TEST] %s", format(res))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := send(ctx, webhookURL, msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}
}
