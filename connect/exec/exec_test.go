package exec

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeSibling is a tiny POSIX-sh sibling connector: it optionally records its
// argv to $FAKE_ARGS_OUT (a shell builtin write, so it runs under an empty env),
// emits two pkg/event.Event JSON lines to stdout, and writes a "cursor:" line to
// stderr — exactly the real sibling contract (aws/main.go:236-249).
const fakeSibling = `#!/bin/sh
if [ -n "$FAKE_ARGS_OUT" ]; then
  printf '%s\n' "$*" > "$FAKE_ARGS_OUT"
fi
printf '%s\n' '{"id":"e1","source":"fake","type":"login"}'
printf '%s\n' '{"id":"e2","source":"fake","type":"logout"}'
printf 'cursor: cur-next\n' 1>&2
`

// sleepSibling blocks longer than any test timeout so the deadline path fires.
const sleepSibling = `#!/bin/sh
sleep 5
printf '%s\n' '{"id":"late"}'
`

// doctorSibling supports --doctor: it prints a single JSON DiagnosisReport on
// stdout and exits 0. Scan args (no --doctor) fall through to the plain event
// behavior so the same fake can double as a Pull fixture if needed.
const doctorSibling = `#!/bin/sh
if [ "$1" = "--doctor" ]; then
  printf '%s\n' '{"diagnosis":{"known":true,"summary":"credentials valid","confidence":0.95},"remediation":[]}'
  exit 0
fi
printf '%s\n' '{"id":"e1","source":"fake","type":"login"}'
`

// noDoctorSibling has no idea what --doctor means: it exits non-zero with a
// usage error on stderr, exactly like an old sibling built before self-
// diagnosis existed.
const noDoctorSibling = `#!/bin/sh
echo "unknown flag: --doctor" 1>&2
exit 2
`

// garbageDoctorSibling "supports" --doctor but prints something that is not a
// valid DiagnosisReport — the malformed-output degrade path.
const garbageDoctorSibling = `#!/bin/sh
printf 'not json\n'
`

// makeFake writes an executable script at dir/name and returns its full path.
func makeFake(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sh-script fake sibling is POSIX-only")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake sibling: %v", err)
	}
	return p
}

func TestPull_ParsesEventsAndPersistsCursor(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", fakeSibling)
	cursorFile := filepath.Join(dir, "cursors", "aws-prod")

	c := New(Spec{
		ID:         "aws-prod",
		Binary:     bin,
		Since:      "24h",
		CursorFile: cursorFile,
	})

	events, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].ID != "e1" || events[1].ID != "e2" {
		t.Fatalf("unexpected events: %+v", events)
	}

	got, err := os.ReadFile(cursorFile)
	if err != nil {
		t.Fatalf("cursor file not persisted: %v", err)
	}
	if strings.TrimSpace(string(got)) != "cur-next" {
		t.Fatalf("cursor = %q, want %q", strings.TrimSpace(string(got)), "cur-next")
	}
}

func TestPull_SubsequentPullSendsCursor(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", fakeSibling)
	cursorFile := filepath.Join(dir, "cursors", "aws-prod")
	argsOut := filepath.Join(dir, "args.txt")

	// The fake records its argv only when FAKE_ARGS_OUT is in its scoped env, so
	// this also proves env pass-through by NAME works.
	t.Setenv("FAKE_ARGS_OUT", argsOut)

	c := New(Spec{
		ID:         "aws-prod",
		Binary:     bin,
		Since:      "24h",
		CursorFile: cursorFile,
		Env:        []string{"FAKE_ARGS_OUT"},
	})

	// First pull: no cursor yet → --since window.
	if _, err := c.Pull(context.Background()); err != nil {
		t.Fatalf("first Pull: %v", err)
	}
	first, _ := os.ReadFile(argsOut)
	if !strings.Contains(string(first), "--since") {
		t.Fatalf("first pull args = %q, want --since", strings.TrimSpace(string(first)))
	}

	// Second pull: the persisted cursor wins → --cursor <persisted>.
	if _, err := c.Pull(context.Background()); err != nil {
		t.Fatalf("second Pull: %v", err)
	}
	second, _ := os.ReadFile(argsOut)
	if !strings.Contains(string(second), "--cursor cur-next") {
		t.Fatalf("second pull args = %q, want --cursor cur-next", strings.TrimSpace(string(second)))
	}
	if strings.Contains(string(second), "--since") {
		t.Fatalf("second pull should not send --since once a cursor exists: %q", strings.TrimSpace(string(second)))
	}
}

func TestPull_ResolvesConventionBinary(t *testing.T) {
	dir := t.TempDir()
	makeFake(t, dir, "mallcop-connector-fake", fakeSibling)
	// No explicit Binary: resolve mallcop-connector-<source> on PATH.
	t.Setenv("PATH", dir)

	c := New(Spec{
		ID:         "fake-1",
		Source:     "fake",
		CursorFile: filepath.Join(dir, "cursors", "fake-1"),
	})
	events, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull via convention binary: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
}

func TestPull_MissingBinaryIsLoud(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // empty dir → nothing to resolve

	c := New(Spec{ID: "aws-prod", Source: "nonexistent-xyz"})
	events, err := c.Pull(context.Background())
	if err == nil {
		t.Fatal("missing sibling binary must be a loud error, got nil")
	}
	if events != nil {
		t.Fatalf("missing binary must return nil events, not %v", events)
	}
	if !strings.Contains(err.Error(), "mallcop-connector-nonexistent-xyz") {
		t.Fatalf("error should name the missing binary: %v", err)
	}
}

func TestPull_TimeoutHonored(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-slow", sleepSibling)

	c := New(Spec{
		ID:      "slow",
		Binary:  bin,
		Timeout: 200 * time.Millisecond,
		Env:     []string{"PATH"}, // the sleep(1) the fake calls needs PATH
	})

	start := time.Now()
	_, err := c.Pull(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout not honored: Pull took %s (sibling sleeps 5s, timeout was 200ms)", elapsed)
	}
}

func TestDiagnose_ParsesJSONReport(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", doctorSibling)

	c := New(Spec{ID: "fake-1", Binary: bin})
	report, err := c.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !report.Diagnosis.Known {
		t.Fatalf("report.Diagnosis.Known = false, want true: %+v", report)
	}
	if report.Diagnosis.Summary != "credentials valid" {
		t.Fatalf("report.Diagnosis.Summary = %q, want %q", report.Diagnosis.Summary, "credentials valid")
	}
	if report.Diagnosis.Confidence != 0.95 {
		t.Fatalf("report.Diagnosis.Confidence = %v, want 0.95", report.Diagnosis.Confidence)
	}
	if report.ConnectorID != "fake-1" {
		t.Fatalf("report.ConnectorID = %q, want %q (defaulted from Spec.ID)", report.ConnectorID, "fake-1")
	}
}

func TestDiagnose_PassesDoctorFlagNotScanArgs(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", fakeSibling)
	argsOut := filepath.Join(dir, "args.txt")
	t.Setenv("FAKE_ARGS_OUT", argsOut)

	// fakeSibling doesn't understand --doctor and will exit non-zero parsing it
	// as an event line — that's fine, Diagnose degrades gracefully. What this
	// test proves is the invocation: --doctor, not --since/--cursor scan args.
	c := New(Spec{ID: "fake-1", Binary: bin, Env: []string{"FAKE_ARGS_OUT"}})
	if _, err := c.Diagnose(context.Background()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	got, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatalf("sibling never recorded argv: %v", err)
	}
	if strings.TrimSpace(string(got)) != "--doctor" {
		t.Fatalf("sibling argv = %q, want exactly %q", strings.TrimSpace(string(got)), "--doctor")
	}
}

func TestDiagnose_NoDoctorSupportDegradesGracefully(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", noDoctorSibling)

	c := New(Spec{ID: "fake-1", Binary: bin})
	report, err := c.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose must degrade gracefully, not return an error: %v", err)
	}
	if report.Diagnosis.Known {
		t.Fatalf("report.Diagnosis.Known = true, want false (sibling has no --doctor support): %+v", report)
	}
	if report.Diagnosis.Summary == "" {
		t.Fatal("degraded report must carry a human-readable Summary, not an empty string")
	}
	if report.ConnectorID != "fake-1" {
		t.Fatalf("report.ConnectorID = %q, want %q even in the degraded case", report.ConnectorID, "fake-1")
	}
}

func TestDiagnose_MalformedOutputDegradesGracefully(t *testing.T) {
	dir := t.TempDir()
	bin := makeFake(t, dir, "mallcop-connector-fake", garbageDoctorSibling)

	c := New(Spec{ID: "fake-1", Binary: bin})
	report, err := c.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose must degrade gracefully on non-JSON output, not return an error: %v", err)
	}
	if report.Diagnosis.Known {
		t.Fatalf("report.Diagnosis.Known = true, want false (sibling printed non-JSON): %+v", report)
	}
}

func TestDiagnose_MissingBinaryDegradesGracefully(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // empty dir → nothing to resolve

	c := New(Spec{ID: "aws-prod", Source: "nonexistent-xyz"})
	report, err := c.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose must degrade gracefully on a missing binary, not return an error: %v", err)
	}
	if report.Diagnosis.Known {
		t.Fatalf("report.Diagnosis.Known = true, want false (binary missing): %+v", report)
	}
	if !strings.Contains(report.Diagnosis.Summary, "mallcop-connector-nonexistent-xyz") {
		t.Fatalf("degraded summary should name the missing binary: %q", report.Diagnosis.Summary)
	}
}
