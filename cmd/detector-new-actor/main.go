// detector-new-actor reads events JSONL from stdin, compares each actor
// against the baseline known-actors set, and emits findings JSONL to stdout
// for actors not seen in the baseline period.
//
// Usage:
//
//	detector-new-actor --baseline <path> < events.jsonl
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

	// Deduplicate findings per actor — one finding per new actor.
	emitted := make(map[string]bool)

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

		f := evaluate(ev, bl, emitted)
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
