// Command baseline builds and queries mallcop baseline frequency tables.
//
// Usage:
//
//	baseline update --window 30d --events events.jsonl --out baseline.json
//	baseline query  --baseline baseline.json --entity user:alice --question known?
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "update":
		if err := runUpdate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "baseline update: %v\n", err)
			os.Exit(1)
		}
	case "query":
		if err := runQuery(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "baseline query: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `baseline — mallcop baseline engine

Commands:
  update  Build a baseline from events
    --window   Duration window (e.g. 30d, 24h). Required.
    --events   Path to events JSONL file. Required.
    --out      Path to write baseline JSON. Required.

  query   Query a baseline
    --baseline  Path to baseline JSON. Required.
    --entity    Entity key to query (e.g. user:alice). Required.
    --question  Question to ask: "known?" (default).`)
}

// runUpdate implements: baseline update --window 30d --events events.jsonl --out baseline.json
func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	windowStr := fs.String("window", "", "Sliding window duration (e.g. 30d, 24h)")
	eventsPath := fs.String("events", "", "Path to events JSONL file")
	outPath := fs.String("out", "", "Output baseline JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *windowStr == "" || *eventsPath == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("--window, --events, and --out are required")
	}

	window, err := parseDuration(*windowStr)
	if err != nil {
		return fmt.Errorf("invalid --window %q: %w", *windowStr, err)
	}

	events, err := loadEvents(*eventsPath)
	if err != nil {
		return fmt.Errorf("loading events: %w", err)
	}

	eng := baseline.NewEngine()
	eng.Update(events, window, time.Now().UTC())

	if err := eng.Save(*outPath); err != nil {
		return fmt.Errorf("saving baseline: %w", err)
	}
	fmt.Printf("wrote baseline with %d entities to %s\n", len(events), *outPath)
	return nil
}

// runQuery implements: baseline query --baseline baseline.json --entity user:alice --question known?
func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "Path to baseline JSON")
	entity := fs.String("entity", "", "Entity key to query")
	question := fs.String("question", "known?", "Question to ask: known?")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *baselinePath == "" || *entity == "" {
		fs.Usage()
		return fmt.Errorf("--baseline and --entity are required")
	}

	eng, err := baseline.LoadEngine(*baselinePath)
	if err != nil {
		return fmt.Errorf("loading baseline: %w", err)
	}

	switch strings.ToLower(*question) {
	case "known?", "known":
		result := eng.IsKnown(*entity)
		fmt.Println(result)
	default:
		return fmt.Errorf("unknown question %q; supported: known?", *question)
	}
	return nil
}

// loadEvents reads newline-delimited JSON events from path.
func loadEvents(path string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []event.Event
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		events = append(events, ev)
	}
	return events, sc.Err()
}

// parseDuration extends time.ParseDuration with day support (e.g. "30d").
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
