// detector-volume-anomaly reads events JSONL from stdin, counts events per
// (source, event_type) group, and emits findings JSONL to stdout when the
// observed count exceeds 3× the baseline count for that group.
//
// Usage:
//
//	detector-volume-anomaly --baseline <path> < events.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
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

	// Collect all events first so we can count per group.
	var events []event.Event
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
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Fatalf("reading stdin: %v", err)
	}

	findings := evaluateAll(events, bl)
	for i := range findings {
		if err := enc.Encode(&findings[i]); err != nil {
			log.Fatalf("encoding finding: %v", err)
		}
	}
}
