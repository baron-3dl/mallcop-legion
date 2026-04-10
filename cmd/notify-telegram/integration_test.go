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

func TestIntegration_Telegram(t *testing.T) {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		t.Skip("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID required for integration test")
	}

	res := resolution.Resolution{
		FindingID:  "integration-test-finding",
		Action:     "alert",
		Reason:     "[TEST] integration test from notify-telegram",
		Confidence: 1.0,
		Actor:      "test-actor",
		Severity:   "low",
		Source:     "notify-telegram-integration-test",
		Timestamp:  time.Now().UTC(),
	}
	msg := fmt.Sprintf("[TEST] %s", format(res))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := send(ctx, token, chatID, msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}
}
