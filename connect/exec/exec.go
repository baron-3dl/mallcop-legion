// Package exec is the process-boundary cloud Connector: it runs a sibling
// connector binary (from the separate mallcop-connectors module) as a child
// process, reads the normalized event JSONL the sibling writes to stdout, and
// captures the incremental cursor the sibling writes to stderr — so that
// `mallcop scan` auto-pulls a cloud source in one pass instead of the manual
// `mallcop-connector-aws > events.jsonl` two-step.
//
// It lives OUTSIDE core/ on purpose. core/connect (the input seam) is pure
// stdlib + pkg/event and forbids transport/SDK/process dependencies via
// core/lint; this package imports os/exec, which the core purity lint would
// reject. The seam is honored by the process boundary itself: mallcop forks a
// process and reads bytes across the seam — it never links a cloud SDK. The
// cloud SDKs stay in the mallcop-connectors module; the sibling binary carries
// them, mallcop does not. This preserves invariant 4 (no SDK in the runtime).
//
// The sibling contract (uniform across aws/azure/gcp/m365/okta/github):
//   - writes one pkg/event.Event JSON object per line to STDOUT,
//   - accepts --since <RFC3339> and --cursor <opaque> flags,
//   - authenticates from environment variables,
//   - emits its next cursor as a "cursor: <value>" line on STDERR.
//
// Because the sibling's stdout is the same events-JSONL the FileConnector
// parses, ExecConnector reuses connect.FromReader — the sibling's output is
// parsed by the exact same code path as `--events -`.
package exec

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// doctorFlag is the flag ExecConnector execs the sibling with in place of scan
// args to ask it to self-diagnose (design §11: the doctor needs a LIVE NETWORK
// CALL, so it ships in the native sibling binary, never as a WASM sidecar).
const doctorFlag = "--doctor"

// cursorPrefix is the token a sibling binary writes on stderr to hand back its
// next incremental cursor: "cursor: <value>". Matches aws/main.go:247.
const cursorPrefix = "cursor:"

// defaultCursorDir is the store-relative directory ExecConnector persists per
// connector cursors under when Spec.CursorFile is not set explicitly.
const defaultCursorDir = ".mallcop/cursors"

// Spec configures one ExecConnector. It is DATA (the config author writes it);
// this loader is human-written, frozen product code.
type Spec struct {
	// ID is the connector's stable identifier (e.g. "aws-prod"). It names the
	// default cursor file (.mallcop/cursors/<id>) when CursorFile is empty and
	// is used in error messages.
	ID string

	// Binary is an explicit path override for the sibling binary. When empty,
	// the binary is resolved by convention from Source: mallcop-connector-<source>.
	Binary string

	// Source is the cloud source name (e.g. "aws"). When Binary is empty it
	// resolves the convention binary name mallcop-connector-<source> on $PATH.
	Source string

	// Args are extra flags passed through to the sibling (e.g. --region us-east-1).
	// --since / --cursor are computed by ExecConnector and prepended; these are
	// appended after.
	Args []string

	// Since is a lookback duration string (e.g. "24h"). On the FIRST pull (no
	// persisted cursor) it becomes --since <now-Since, RFC3339>. Once a cursor
	// has been persisted, the cursor wins and Since is ignored — the scan is
	// incremental from then on.
	Since string

	// CursorFile is where the sibling's next cursor is persisted (and read from
	// on the next pull). Empty → .mallcop/cursors/<ID>.
	CursorFile string

	// Env is the list of environment variable NAMES to pass through to the
	// sibling (e.g. AWS_ACCESS_KEY_ID). Only these names are forwarded, resolved
	// from the current process environment — never inline secret VALUES, and the
	// values are never logged. A name absent from the environment is skipped.
	Env []string

	// Timeout bounds the child process (from budgets.scan_timeout). Zero means no
	// per-connector deadline beyond the caller's ctx.
	Timeout time.Duration
}

// ExecConnector runs a sibling connector binary and adapts its stdout JSONL to
// []event.Event across the connect seam.
type ExecConnector struct {
	spec Spec
}

// compile-time proof ExecConnector satisfies the input seam, and its optional
// self-diagnosis extension. FileConnector does NOT implement Diagnosable — a
// local file either opens or it doesn't; there is nothing to diagnose.
var (
	_ connect.Connector   = (*ExecConnector)(nil)
	_ connect.Diagnosable = (*ExecConnector)(nil)
)

// New returns an ExecConnector for spec. Construction touches neither the
// filesystem nor the process table — resolution and exec happen at Pull time.
func New(spec Spec) *ExecConnector {
	return &ExecConnector{spec: spec}
}

// binaryName returns the name/path to resolve: the explicit Binary override, or
// the convention mallcop-connector-<source>.
func (c *ExecConnector) binaryName() (string, error) {
	if c.spec.Binary != "" {
		return c.spec.Binary, nil
	}
	if c.spec.Source == "" {
		return "", fmt.Errorf("connect/exec: connector %q has neither binary nor source set", c.spec.ID)
	}
	return "mallcop-connector-" + c.spec.Source, nil
}

// cursorPath returns the file this connector persists/reads its cursor at.
func (c *ExecConnector) cursorPath() string {
	if c.spec.CursorFile != "" {
		return c.spec.CursorFile
	}
	id := c.spec.ID
	if id == "" {
		id = c.spec.Source
	}
	return filepath.Join(defaultCursorDir, id)
}

// Pull resolves the sibling binary, execs it with the computed --since/--cursor
// window, parses its stdout as events (same path as --events -), persists the
// next cursor from stderr, and returns the normalized batch.
//
// A MISSING binary is a LOUD error, never an empty batch: a configured source
// that cannot run must halt the scan, not silently under-report (a dropped
// source would tell the operator the source was scanned when it was not).
func (c *ExecConnector) Pull(ctx context.Context) ([]event.Event, error) {
	name, err := c.binaryName()
	if err != nil {
		return nil, err
	}

	// Resolve on $PATH (or verify the explicit path is executable). A missing
	// binary fails loud here, before any process is started.
	bin, err := osexec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("connect/exec: connector %q: sibling binary %q not found on PATH "+
			"(a configured cloud source that cannot run halts the scan; install it or remove the connector): %w",
			c.spec.ID, name, err)
	}

	args, err := c.buildArgs()
	if err != nil {
		return nil, err
	}

	// Honor the per-connector timeout on top of the caller's ctx.
	runCtx := ctx
	if c.spec.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, c.spec.Timeout)
		defer cancel()
	}

	cmd := osexec.CommandContext(runCtx, bin, args...)
	// Scope credentials: forward ONLY the named env vars, never the full
	// environment. The binary was resolved to an absolute path, so no PATH is
	// needed to exec it. Values are read from the process env and never logged.
	cmd.Env = c.childEnv()
	// On deadline, kill the whole process group (a shell-wrapper sibling may fork
	// grandchildren that hold the stdout pipe) and force the pipes closed shortly
	// after so Wait cannot hang past the timeout.
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("connect/exec: connector %q: stdout pipe: %w", c.spec.ID, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("connect/exec: connector %q: start %s: %w", c.spec.ID, bin, err)
	}

	// Parse the sibling's stdout with the SAME parser as --events - / stdin.
	// FromReader materializes the whole batch, draining the pipe before Wait.
	events, pullErr := connect.FromReader(stdout).Pull(runCtx)

	waitErr := cmd.Wait()
	if waitErr != nil {
		return nil, fmt.Errorf("connect/exec: connector %q: sibling %s failed: %w (stderr: %s)",
			c.spec.ID, bin, waitErr, stderrTail(&stderr))
	}
	if pullErr != nil {
		return nil, fmt.Errorf("connect/exec: connector %q: parse sibling output: %w", c.spec.ID, pullErr)
	}

	// Persist the next cursor (if the sibling emitted one) so the next scan is
	// incremental. Only on a fully clean run.
	if cur := parseCursor(&stderr); cur != "" {
		if err := c.persistCursor(cur); err != nil {
			return nil, fmt.Errorf("connect/exec: connector %q: persist cursor: %w", c.spec.ID, err)
		}
	}

	return events, nil
}

// Diagnose asks the sibling binary to self-check by execing it with --doctor
// instead of the scan args, and parses its stdout as a single JSON
// connect.DiagnosisReport (design §3/§11). It reuses the same binary
// resolution, scoped env, and process/timeout scaffolding as Pull.
//
// Diagnose never returns a raw, uninterpreted error for an EXPECTED degraded
// case — a missing sibling binary, a sibling that doesn't understand
// --doctor, or one that prints something that isn't a valid DiagnosisReport —
// each of those becomes a DiagnosisReport with Diagnosis.Known == false and a
// nil error, so a caller (mallcop doctor, chat) always has a structured report
// to show instead of a crash. A non-nil error is reserved for something the
// caller truly cannot recover a report from: ctx cancellation before the child
// could even be started.
func (c *ExecConnector) Diagnose(ctx context.Context) (connect.DiagnosisReport, error) {
	if err := ctx.Err(); err != nil {
		return connect.DiagnosisReport{}, fmt.Errorf("connect/exec: connector %q: diagnose: %w", c.spec.ID, err)
	}

	name, err := c.binaryName()
	if err != nil {
		return connect.DiagnosisReport{}, err
	}

	bin, err := osexec.LookPath(name)
	if err != nil {
		return degradedReport(c.spec.ID, fmt.Sprintf(
			"sibling binary %q not found on PATH (install it, or this connector cannot self-diagnose)", name)), nil
	}

	// Honor the per-connector timeout on top of the caller's ctx, same as Pull.
	runCtx := ctx
	if c.spec.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, c.spec.Timeout)
		defer cancel()
	}

	cmd := osexec.CommandContext(runCtx, bin, doctorFlag)
	cmd.Env = c.childEnv()
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return degradedReport(c.spec.ID, fmt.Sprintf(
			"sibling %s does not support %s: %v (stderr: %s)", bin, doctorFlag, err, stderrTail(&stderr))), nil
	}

	var report connect.DiagnosisReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		return degradedReport(c.spec.ID, fmt.Sprintf(
			"sibling %s printed a non-JSON %s report: %v", bin, doctorFlag, err)), nil
	}
	if report.ConnectorID == "" {
		report.ConnectorID = c.spec.ID
	}
	return report, nil
}

// degradedReport builds the graceful-degradation DiagnosisReport Diagnose
// returns (with a nil error) when the sibling cannot be asked to self-diagnose
// at all — Known:false is itself a valid, structured answer, never a crash.
func degradedReport(connectorID, summary string) connect.DiagnosisReport {
	return connect.DiagnosisReport{
		ConnectorID: connectorID,
		Diagnosis: connect.Diagnosis{
			Known:   false,
			Summary: summary,
		},
	}
}

// buildArgs computes the incremental window flags then appends the caller Args.
// A persisted cursor wins over Since (incremental from the last checkpoint);
// only the FIRST pull (no cursor yet) uses --since <now-Since>.
func (c *ExecConnector) buildArgs() ([]string, error) {
	var args []string

	cursor, err := c.readCursor()
	if err != nil {
		return nil, err
	}
	switch {
	case cursor != "":
		args = append(args, "--cursor", cursor)
	case c.spec.Since != "":
		d, err := time.ParseDuration(c.spec.Since)
		if err != nil {
			return nil, fmt.Errorf("connect/exec: connector %q: invalid since %q (want a Go duration like 24h): %w",
				c.spec.ID, c.spec.Since, err)
		}
		args = append(args, "--since", time.Now().Add(-d).UTC().Format(time.RFC3339))
	}

	args = append(args, c.spec.Args...)
	return args, nil
}

// childEnv returns the scoped environment for the sibling: only the named
// pass-through variables that are actually set in the current process env.
func (c *ExecConnector) childEnv() []string {
	env := make([]string, 0, len(c.spec.Env))
	for _, name := range c.spec.Env {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// readCursor returns the persisted cursor for this connector, or "" if none.
func (c *ExecConnector) readCursor() (string, error) {
	b, err := os.ReadFile(c.cursorPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("connect/exec: connector %q: read cursor %s: %w", c.spec.ID, c.cursorPath(), err)
	}
	return strings.TrimSpace(string(b)), nil
}

// persistCursor writes cur to the cursor file, creating parent dirs.
func (c *ExecConnector) persistCursor(cur string) error {
	p := c.cursorPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(cur+"\n"), 0o600)
}

// parseCursor scans the sibling's stderr for the LAST "cursor: <value>" line and
// returns the trimmed value, or "" if the sibling emitted no cursor.
func parseCursor(stderr *bytes.Buffer) string {
	var cur string
	sc := bufio.NewScanner(bytes.NewReader(stderr.Bytes()))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, cursorPrefix); ok {
			cur = strings.TrimSpace(rest)
		}
	}
	return cur
}

// stderrTail returns the last few lines of stderr for an error message, so a
// sibling failure surfaces its diagnostics without dumping an unbounded blob.
func stderrTail(stderr *bytes.Buffer) string {
	s := strings.TrimSpace(stderr.String())
	if s == "" {
		return "(empty)"
	}
	lines := strings.Split(s, "\n")
	const max = 5
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return strings.Join(lines, " | ")
}
