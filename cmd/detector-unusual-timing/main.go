// detector-unusual-timing reads events JSONL from stdin and emits findings
// JSONL to stdout for events that occur at UTC hours not seen for that actor
// in the baseline period.
//
// Usage:
//
//	detector-unusual-timing --baseline <path> < events.jsonl
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
