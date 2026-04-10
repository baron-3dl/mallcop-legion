// detector-unusual-login reads events JSONL from stdin, compares each login
// event against a baseline of known user patterns, and emits findings JSONL
// to stdout for logins that deviate from baseline.
//
// Usage:
//
//	detector-unusual-login --baseline <path> < events.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

func main() {
	baselinePath := flag.String("baseline", "", "path to baseline JSON file (required)")
	flag.Parse()

	if *baselinePath == "" {
		log.Fatal("--baseline is required")
	}

	bl, err := baseline.Load(*baselinePath)
	if err != nil {
		log.Fatalf("loading baseline: %v", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("skipping malformed event: %v", err)
			continue
		}

		f := evaluate(ev, bl)
		if f == nil {
			continue
		}

		if err := enc.Encode(f); err != nil {
			log.Fatalf("encoding finding: %v", err)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Fatalf("reading stdin: %v", err)
	}
}

// loginPayload is the expected structure inside Event.Payload for login events.
type loginPayload struct {
	IP  string `json:"ip"`
	Geo string `json:"geo"`
}

// evaluate returns a Finding if the event is unusual, or nil if it is benign
// or not a login event.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, bl *baseline.Baseline) *finding.Finding {
	if ev.Type != "login" {
		return nil
	}

	var lp loginPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &lp)
	}

	evidence, _ := json.Marshal(map[string]string{
		"ip":       lp.IP,
		"geo":      lp.Geo,
		"event_id": ev.ID,
	})

	if !bl.HasUser(ev.Actor) {
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:unusual-login",
			Severity:  "high",
			Type:      "unusual-login",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    "login from unrecognized user account",
			Evidence:  evidence,
		}
	}

	if bl.KnownIP(ev.Actor, lp.IP) {
		// Known user, known IP — benign.
		return nil
	}

	if bl.KnownGeo(ev.Actor, lp.Geo) {
		// Known user, new IP, but geo is familiar — low severity.
		return &finding.Finding{
			ID:        "finding-" + ev.ID,
			Source:    "detector:unusual-login",
			Severity:  "low",
			Type:      "unusual-login",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("login from new IP in known region (%s)", lp.Geo),
			Evidence:  evidence,
		}
	}

	// Known user, unknown IP, unknown geo — high severity.
	return &finding.Finding{
		ID:        "finding-" + ev.ID,
		Source:    "detector:unusual-login",
		Severity:  "high",
		Type:      "unusual-login",
		Actor:     ev.Actor,
		Timestamp: ev.Timestamp,
		Reason:    fmt.Sprintf("login from unknown location (IP: %s, geo: %s)", lp.IP, lp.Geo),
		Evidence:  evidence,
	}
}
