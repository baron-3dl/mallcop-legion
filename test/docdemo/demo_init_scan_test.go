//go:build docdemo

package docdemo

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDemo_Init proves README.md's "Initialize" demo:
//
//	$ mallcop init
//
// against the shown output block, verbatim after <dir> normalization (see
// normalize.go). This is the exact bug this harness exists to catch: the doc
// used to show a bare "mallcop.yaml" with no directory prefix, but the real
// binary always prints the absolute --dir path (cli/init.go: `created %s`).
// README.md was fixed (as part of this item) to show "<dir>/mallcop.yaml" etc.
func TestDemo_Init(t *testing.T) {
	bin := buildMallcop(t)
	dir := t.TempDir()

	doc := readDoc(t, "README.md")
	const shown = "mallcop init: created <dir>/mallcop.yaml (config — offline inference)\n" +
		"mallcop init: created <dir>/store/ (findings store)\n" +
		"mallcop init: created <dir>/events.jsonl (sample events)\n" +
		"\n" +
		"Next steps:\n" +
		"  1. Run the scan (reads mallcop.yaml — no flags needed):\n" +
		"       mallcop scan\n" +
		"  2. Add a source: edit mallcop.yaml -> connectors:\n" +
		"     (a github org, or a cloud source like aws/azure)\n" +
		"  3. For managed LLM resolution (offline is the fail-safe default):\n" +
		"       mallcop init --pro  &&  export MALLCOP_API_KEY=mallcop-sk-...\n"
	mustContain(t, "README.md", doc, shown, "`mallcop init` output")

	stdout, stderr, code := run(t, dir, bin, nil, "init")
	if code != 0 {
		t.Fatalf("mallcop init: exit %d, stderr=%s", code, stderr)
	}
	got := normalizeDynamic(stdout, dir)
	// dir itself may appear via its EvalSymlinks-resolved form (macOS /tmp is a
	// symlink to /private/tmp) — normalize both spellings defensively.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		got = normalizeDynamic(got, resolved)
	}
	if got != shown {
		t.Fatalf("mallcop init output drifted from README.md's shown demo.\n--- doc says ---\n%s\n--- real (normalized) ---\n%s", shown, got)
	}
}

// TestDemo_Scan proves README.md's "Run the scan" + "Inspect what was
// recorded" demos, chained (scan then status, exactly as a reader would run
// them after `mallcop init`):
//
//	$ mallcop scan
//	$ mallcop status --store store
func TestDemo_Scan(t *testing.T) {
	bin := buildMallcop(t)
	dir := t.TempDir()

	if _, stderr, code := run(t, dir, bin, nil, "init"); code != 0 {
		t.Fatalf("setup: mallcop init: exit %d, stderr=%s", code, stderr)
	}

	doc := readDoc(t, "README.md")

	const scanShown = "Scan complete\n" +
		"  Events scanned:     1\n" +
		"  Findings detected:  2\n" +
		"  Escalated:          2\n" +
		"  Resolved:           0\n" +
		"  Investigated:       0\n" +
		"  Investigations degraded: 2\n"
	mustContain(t, "README.md", doc, scanShown, "`mallcop scan` output")

	stdout, stderr, code := run(t, dir, bin, nil, "scan")
	if code != 1 {
		t.Fatalf("mallcop scan: want exit 1 (findings present), got %d, stderr=%s", code, stderr)
	}
	if stdout != scanShown {
		t.Fatalf("mallcop scan output drifted from README.md's shown demo.\n--- doc says ---\n%s\n--- real ---\n%s", scanShown, stdout)
	}

	const statusShown = "Store:      store\n" +
		"Findings:   2 recorded\n" +
		"Decisions:  2 recorded\n" +
		"Cases:      2 open (0 recurring)\n" +
		"  injection-probe  entity=(no entity)  count=1  cadence=no established cadence  status=open\n" +
		"  new-actor  entity=(no entity)  count=1  cadence=no established cadence  status=open\n" +
		"Coverage gaps:   0 (0 reported miss)\n" +
		"State:      idle\n"
	mustContain(t, "README.md", doc, statusShown, "`mallcop status --store store` output")

	stdout, stderr, code = run(t, dir, bin, nil, "status", "--store", "store")
	if code != 0 {
		t.Fatalf("mallcop status: exit %d, stderr=%s", code, stderr)
	}
	if stdout != statusShown {
		t.Fatalf("mallcop status output drifted from README.md's shown demo.\n--- doc says ---\n%s\n--- real ---\n%s", statusShown, stdout)
	}
}

// TestDemo_ConfigSetConnector_Smoke runs README.md's `mallcop config set
// connector ...` demo command. The doc shows no output block for it, so this
// only proves the exact shown command still executes cleanly (exit 0) against
// the real binary — a smoke check, not an output assertion. See registry.
func TestDemo_ConfigSetConnector_Smoke(t *testing.T) {
	bin := buildMallcop(t)
	dir := t.TempDir()
	if _, stderr, code := run(t, dir, bin, nil, "init"); code != 0 {
		t.Fatalf("setup: mallcop init: exit %d, stderr=%s", code, stderr)
	}
	doc := readDoc(t, "README.md")
	const shownCmd = "mallcop config set connector --kind=github --id=my-org --org=my-org"
	mustContain(t, "README.md", doc, shownCmd, "`mallcop config set connector` command")

	_, stderr, code := run(t, dir, bin, nil, "config", "set", "connector", "--kind=github", "--id=my-org", "--org=my-org")
	if code != 0 {
		t.Fatalf("shown command %q: exit %d, stderr=%s", shownCmd, code, stderr)
	}
}

// TestDemo_ConfigSetAutonomy_Smoke runs README.md's `mallcop config set
// autonomy semi` demo command (no output block shown — smoke only).
func TestDemo_ConfigSetAutonomy_Smoke(t *testing.T) {
	bin := buildMallcop(t)
	dir := t.TempDir()
	if _, stderr, code := run(t, dir, bin, nil, "init"); code != 0 {
		t.Fatalf("setup: mallcop init: exit %d, stderr=%s", code, stderr)
	}
	doc := readDoc(t, "README.md")
	const shownCmd = "mallcop config set autonomy semi"
	mustContain(t, "README.md", doc, shownCmd, "`mallcop config set autonomy` command")

	_, stderr, code := run(t, dir, bin, nil, "config", "set", "autonomy", "semi")
	if code != 0 {
		t.Fatalf("shown command %q: exit %d, stderr=%s", shownCmd, code, stderr)
	}
}

// TestDemo_ScanVariants_Smoke covers the two offline-reproducible forms of
// README.md's "### mallcop scan" 3-variant block: the zero-flag form (reads
// mallcop.yaml, already byte-tested by TestDemo_Scan) and the explicit
// --events/--store form. The --connector github form needs a live GitHub org
// and is registered out-of-reach (not run here).
func TestDemo_ScanVariants_Smoke(t *testing.T) {
	bin := buildMallcop(t)
	dir := t.TempDir()
	if _, stderr, code := run(t, dir, bin, nil, "init"); code != 0 {
		t.Fatalf("setup: mallcop init: exit %d, stderr=%s", code, stderr)
	}
	doc := readDoc(t, "README.md")
	mustContain(t, "README.md", doc, "mallcop scan --events events.jsonl --store store", "`mallcop scan --events ... --store ...` command")

	_, stderr, code := run(t, dir, bin, nil, "scan", "--events", "events.jsonl", "--store", "store2")
	if code != 1 {
		t.Fatalf("mallcop scan --events events.jsonl --store store2: want exit 1 (findings present), got %d, stderr=%s", code, stderr)
	}
}

// TestDemo_E2EScan proves docs/demo/e2e-scan.md end to end: the scan command
// (run WITHOUT the doc's illustrative BYOK env vars — see registry entry for
// why: forge.example is a placeholder host, not real, and setting it would
// attempt live network I/O) and the git-store readback, against the shown
// JSON summary and the shown (elided) resolutions.jsonl lines.
func TestDemo_E2EScan(t *testing.T) {
	bin := buildMallcop(t)
	mallcopRoot := repoRoot(t)
	storeDir := filepath.Join(t.TempDir(), "mallcop-demo-store")

	doc := readDoc(t, "docs/demo/e2e-scan.md")
	mustContain(t, "docs/demo/e2e-scan.md", doc,
		"mallcop scan \\\n  --events   docs/demo/events.jsonl \\\n  --baseline docs/demo/baseline.json \\\n  --store    /tmp/mallcop-demo-store \\\n  --json",
		"`mallcop scan` command")

	const jsonShown = "{\n" +
		"  \"events_scanned\": 2,\n" +
		"  \"findings_detected\": 2,\n" +
		"  \"escalated\": 2,\n" +
		"  \"resolved\": 0,\n" +
		"  \"investigations_degraded\": 2\n" +
		"}\n"
	mustContain(t, "docs/demo/e2e-scan.md", doc,
		"\"events_scanned\": 2,\n  \"findings_detected\": 2,\n  \"escalated\": 2,\n  \"resolved\": 0,\n  \"investigations_degraded\": 2",
		"expected JSON summary")

	stdout, stderr, code := run(t, mallcopRoot, bin, nil,
		"scan",
		"--events", "docs/demo/events.jsonl",
		"--baseline", "docs/demo/baseline.json",
		"--store", storeDir,
		"--json")
	if code != 1 {
		t.Fatalf("mallcop scan (e2e-scan.md demo): want exit 1 (findings present), got %d, stderr=%s", code, stderr)
	}
	if stdout != jsonShown {
		t.Fatalf("e2e-scan.md JSON summary drifted.\n--- doc says ---\n%s\n--- real ---\n%s", jsonShown, stdout)
	}

	mustContain(t, "docs/demo/e2e-scan.md", doc, "git -C /tmp/mallcop-demo-store show HEAD:resolutions.jsonl", "`git show` command")
	stdout, stderr, code = run(t, "", "git", nil, "-C", storeDir, "show", "HEAD:resolutions.jsonl")
	if code != 0 {
		t.Fatalf("git show HEAD:resolutions.jsonl: exit %d, stderr=%s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("resolutions.jsonl: want 2 lines, got %d:\n%s", len(lines), stdout)
	}
	// The doc shows an ABBREVIATED example of each line: a subset of the real
	// fields (finding_id/action/actor/source/reason), with "..." eliding the
	// middle of the (real, multi-line) reason text and omitting fields the
	// doc doesn't call out (confidence/severity/timestamp). Documented
	// normalization for this block: subset-key match (every key present in
	// the doc's JSON must match the real line; extra real keys not shown in
	// the doc are allowed) + "..." wildcard substring match for elided text.
	// This is NOT a skip — every doc-shown key/prefix/suffix is verified
	// against the real captured line.
	assertJSONLLineMatchesElidedExample(t, lines[0],
		`{"finding_id":"finding-evt-001","action":"escalate","actor":"ext-contractor-9f","source":"detector:new-actor","reason":"..."}`)
	assertJSONLLineMatchesElidedExample(t, lines[1],
		`{"finding_id":"finding-evt-001","action":"escalate","actor":"ext-contractor-9f","source":"detector:priv-escalation","reason":"Privilege escalation / role grant / permission-boundary change always requires human audit. ... No LLM involved."}`)
}
