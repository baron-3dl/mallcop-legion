// Command mallcop is the customer-facing CLI for running mallcop scans.
//
// Usage:
//
//	mallcop scan   [--chart <path>] [--timeout <duration>] [--json]
//	mallcop init   [--dir <path>]
//	mallcop status [--chart <path>]
//	mallcop config [--chart <path>]
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	var err error
	switch cmd {
	case "scan":
		err = runScan(args)
	case "init":
		err = runInit(args)
	case "status":
		err = runStatus(args)
	case "config":
		err = runConfig(args)
	default:
		fmt.Fprintf(os.Stderr, "mallcop: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		if isFindingsError(err) {
			// exit 1 = findings detected (not an error condition)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "mallcop %s: %v\n", cmd, err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mallcop — security scan CLI

Commands:
  scan    Run a one-shot security scan cycle
    --chart    Path to the legion chart TOML (default: charts/vertical-slice.toml)
    --timeout  Max time to wait for scan completion (default: 10m)
    --json     Output results as JSON

  init    Initialize a mallcop config directory
    --dir      Directory to initialize (default: current directory)

  status  Show current scan state
    --chart    Path to the legion chart TOML (default: charts/vertical-slice.toml)

  config  Print and validate the current config
    --chart    Path to the legion chart TOML (default: charts/vertical-slice.toml)

Exit codes (scan):
  0  No findings
  1  Findings present
  2  Scan failure`)
}
