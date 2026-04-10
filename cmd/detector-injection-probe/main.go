// detector-injection-probe reads events JSONL from stdin and emits findings
// JSONL to stdout for events that contain prompt injection attempts in their
// payload fields. This is SECURITY-CRITICAL: it must catch hostile inputs
// including obfuscated and encoded injection strings.
//
// Usage:
//
//	detector-injection-probe --baseline <path> < events.jsonl
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

	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size to handle large payloads with encoded injection strings.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
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

		findings := evaluate(ev, bl)
		for i := range findings {
			if err := enc.Encode(&findings[i]); err != nil {
				log.Fatalf("encoding finding: %v", err)
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Fatalf("reading stdin: %v", err)
	}
}
