package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

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

	subject, body := format(res)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := send(ctx, cfg, subject, body); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send email: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	SMTPHost string
	SMTPPort string
	From     string
	To       string
	Password string // optional — omit for unauthenticated SMTP (e.g. Mailhog)
}

func configFromEnv() (config, error) {
	cfg := config{
		SMTPHost: os.Getenv("SMTP_HOST"),
		SMTPPort: os.Getenv("SMTP_PORT"),
		From:     os.Getenv("SMTP_FROM"),
		To:       os.Getenv("SMTP_TO"),
		Password: os.Getenv("SMTP_PASSWORD"),
	}
	if cfg.SMTPHost == "" {
		return cfg, fmt.Errorf("SMTP_HOST is required")
	}
	if cfg.SMTPPort == "" {
		return cfg, fmt.Errorf("SMTP_PORT is required")
	}
	if cfg.From == "" {
		return cfg, fmt.Errorf("SMTP_FROM is required")
	}
	if cfg.To == "" {
		return cfg, fmt.Errorf("SMTP_TO is required")
	}
	return cfg, nil
}

func format(res resolution.Resolution) (subject, body string) {
	subject = fmt.Sprintf("mallcop: %s — finding %s", strings.ToUpper(res.Action), res.FindingID)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("mallcop: %s\n\n", strings.ToUpper(res.Action)))
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
	body = sb.String()
	return
}

func send(_ context.Context, cfg config, subject, body string) error {
	addr := fmt.Sprintf("%s:%s", cfg.SMTPHost, cfg.SMTPPort)

	msg := []byte(
		"From: " + cfg.From + "\r\n" +
			"To: " + cfg.To + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			body + "\r\n",
	)

	if cfg.Password != "" {
		auth := smtp.PlainAuth("", cfg.From, cfg.Password, cfg.SMTPHost)
		if err := smtp.SendMail(addr, auth, cfg.From, []string{cfg.To}, msg); err != nil {
			return fmt.Errorf("smtp sendmail: %w", err)
		}
	} else {
		// Unauthenticated — suitable for Mailhog or internal relay
		c, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		defer c.Close()

		if err := c.Mail(cfg.From); err != nil {
			return fmt.Errorf("smtp MAIL FROM: %w", err)
		}
		if err := c.Rcpt(cfg.To); err != nil {
			return fmt.Errorf("smtp RCPT TO: %w", err)
		}
		wc, err := c.Data()
		if err != nil {
			return fmt.Errorf("smtp DATA: %w", err)
		}
		defer wc.Close()
		if _, err := wc.Write(msg); err != nil {
			return fmt.Errorf("smtp write body: %w", err)
		}
	}
	return nil
}
