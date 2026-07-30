// Package connect is the INPUT seam of the scan pipeline: it turns a source of
// raw activity into the normalized []event.Event the detector floor consumes.
//
// A Connector is the single abstraction. The product ships one universal
// Connector here — FileConnector, which reads events as JSON-Lines from a file
// path or from stdin — so a scan is runnable with NO cloud credentials and NO
// network at all (point it at an exported events file). The real cloud
// connectors (AWS CloudTrail, GitHub audit log, …) are later waves that plug
// into this SAME interface; the pipeline (core/pipeline) cannot tell a file
// connector from a live cloud connector, which is the point of the seam.
//
// IMPORT DISCIPLINE: this package carries NO inference, transport, framework, or
// cloud-SDK dependency. It is pure stdlib + pkg/event. The core import-lint
// (core/lint) fails the build if that ever changes. A real cloud connector that
// needs an SDK lives OUTSIDE core/ and adapts its output to []event.Event before
// handing it across this seam.
package connect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// Connector pulls a batch of normalized events from one source.
//
// Pull returns the full event batch for one scan cycle. A connector that
// streams internally still returns the materialized slice — the detector floor
// (core/detect) is whole-corpus (volume-anomaly et al. need the full slice), so
// the pipeline works on a materialized batch, not a stream. ctx carries
// cancellation/deadline; a connector that does I/O MUST honor it.
//
// Implementations are expected to be pure with respect to shared state: two
// Pull calls on two connectors never race through this interface. The pipeline
// calls Pull exactly once per scan.
type Connector interface {
	// Pull returns the normalized events for this scan cycle, or an error if the
	// source could not be read. An empty (non-nil-error) batch is valid — a scan
	// over zero events is a clean scan, not a failure.
	Pull(ctx context.Context) ([]event.Event, error)
}

// Diagnosable is an OPTIONAL extension a Connector may implement to support
// self-diagnosis: instead of a caller having to parse a raw Pull error, a
// Diagnosable connector can be asked directly why it cannot pull and returns a
// structured DiagnosisReport (see diagnose.go). FileConnector does not
// implement this — a local file either opens or it doesn't, there is nothing
// to diagnose. ExecConnector does — the sibling binary is where a live
// network/credential probe can run (see connect/exec).
type Diagnosable interface {
	// ID returns the connector's stable identifier — the SAME value Diagnose
	// defaults DiagnosisReport.ConnectorID to when a report leaves it empty.
	// It does no I/O and never fails: a caller holding only the composed
	// Connector (core/pipeline's grantwiring, wiring mallcoppro-d3f's Route 2)
	// uses it to look up whether THIS connector has a pending GRANT-MISS on
	// the grants stream before paying for a live Diagnose call — a healthy
	// connector with nothing outstanding costs one cheap store read, not a
	// re-probe.
	ID() string

	// Diagnose asks the connector to self-check and report structured
	// findings. It MUST NOT surface an expected degraded case (e.g. a sibling
	// binary with no --doctor support) as a raw, uninterpreted error — that
	// case is itself a DiagnosisReport with Diagnosis.Known == false. Diagnose
	// returns a non-nil error only when it cannot produce a report at all
	// (e.g. ctx cancellation).
	Diagnose(ctx context.Context) (DiagnosisReport, error)
}

// FileConnector reads events as JSON-Lines from a file path, or from stdin when
// Path is "-" or empty and Stdin is supplied. It is the credential-free default
// connector: a scan over an exported events.jsonl needs no cloud access.
//
// The zero value is not usable on its own; construct with FromPath or FromReader.
type FileConnector struct {
	// path is the source file; "-" (or empty, with reader set) means stdin.
	path string
	// reader, when non-nil, is read directly (stdin or an in-memory source) and
	// path is ignored. Lets tests and the `-`/stdin case share one code path.
	reader io.Reader
}

// FromPath returns a FileConnector that reads events JSONL from the file at
// path. A path of "-" reads from os.Stdin. The file is opened at Pull time (not
// here) so construction never touches the filesystem.
func FromPath(path string) *FileConnector {
	return &FileConnector{path: path}
}

// FromReader returns a FileConnector that reads events JSONL from r. This is the
// stdin path (FromReader(os.Stdin)) and the test seam (FromReader(strings.NewReader(…))).
func FromReader(r io.Reader) *FileConnector {
	return &FileConnector{reader: r}
}

// compile-time proof FileConnector satisfies the seam.
var _ Connector = (*FileConnector)(nil)

// Pull reads and parses the events JSONL source. Blank lines are skipped; a
// malformed line is a hard error (a corrupt event source must not silently drop
// records the operator believes were scanned — fail loud, do not under-report).
//
// ctx is honored: a cancelled context aborts the read between lines. The source
// is fully materialized into a slice — the detector floor is whole-corpus.
func (c *FileConnector) Pull(ctx context.Context) ([]event.Event, error) {
	r, closeFn, err := c.open()
	if err != nil {
		return nil, err
	}
	defer closeFn()

	var events []event.Event
	scanner := bufio.NewScanner(r)
	// Allow long lines (large payloads) — match the detector binaries' 1 MiB cap.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		// Honor cancellation between records so a huge source aborts promptly.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect: cancelled after %d events: %w", len(events), err)
		}
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("connect: malformed event on line %d: %w", line, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("connect: read events: %w", err)
	}
	return events, nil
}

// open resolves the source: an explicit reader, stdin (path "-" or empty), or a
// file. It returns the reader, a close func (no-op for stdin/reader), and an
// error.
func (c *FileConnector) open() (io.Reader, func(), error) {
	if c.reader != nil {
		return c.reader, func() {}, nil
	}
	if c.path == "" || c.path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(c.path)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: open events file %q: %w", c.path, err)
	}
	return f, func() { _ = f.Close() }, nil
}
