package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

type config struct {
	Token  string
	ChatID string
}

func configFromEnv() (config, error) {
	cfg := config{
		Token:  os.Getenv("TELEGRAM_BOT_TOKEN"),
		ChatID: os.Getenv("TELEGRAM_CHAT_ID"),
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("TELEGRAM_BOT_TOKEN is required")
	}
	if cfg.ChatID == "" {
		return cfg, fmt.Errorf("TELEGRAM_CHAT_ID is required")
	}
	return cfg, nil
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var res resolution.Resolution
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse resolution JSON: %v\n", err)
		os.Exit(1)
	}

	msg := format(res)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := send(ctx, cfg.Token, cfg.ChatID, msg); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send Telegram message: %v\n", err)
		os.Exit(1)
	}
}

func format(res resolution.Resolution) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("mallcop: %s\n", strings.ToUpper(res.Action)))
	sb.WriteString(fmt.Sprintf("Finding: %s\n", res.FindingID))
	if res.Actor != "" {
		sb.WriteString(fmt.Sprintf("Actor: %s\n", res.Actor))
	}
	if res.Severity != "" {
		sb.WriteString(fmt.Sprintf("Severity: %s\n", res.Severity))
	}
	if res.Source != "" {
		sb.WriteString(fmt.Sprintf("Source: %s\n", res.Source))
	}
	if res.Reason != "" {
		sb.WriteString(fmt.Sprintf("Reason: %s\n", res.Reason))
	}
	if res.Confidence > 0 {
		sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", res.Confidence*100))
	}
	if !res.Timestamp.IsZero() {
		sb.WriteString(fmt.Sprintf("Time: %s\n", res.Timestamp.UTC().Format(time.RFC3339)))
	}
	return sb.String()
}

func send(ctx context.Context, token, chatID, text string) error {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("text", text)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned %d", resp.StatusCode)
	}
	return nil
}
