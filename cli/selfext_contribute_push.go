package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/selfext/contribback"
)

// contribPushRunner runs one external command with a working directory ("" =
// inherit cwd) and returns its combined output. A package-level seam so a
// test can drive the REAL git plumbing end to end against a REAL local git
// remote (a bare repo on disk) instead of the network — nothing about `git`
// itself is faked here, only which remote it talks to (a filesystem path
// instead of an https://github.com/... URL, which `git clone`/`git push`
// treat identically).
var contribPushRunner = func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

// contribCommitName/contribCommitEmail are the git commit author recorded on
// a materialized contribute-back commit. This is NOT the PR-opener identity —
// the PR itself still opens under the operator's own `gh auth` account (R8);
// this is only the commit metadata, mirroring the "mallcop-store" identity
// openOrInitStore (cli/scan.go) already stamps on the local store's own git
// commits. Passed via `-c` flags (not global git config) so this never
// depends on — or mutates — the operator's own git identity.
const (
	contribCommitName  = "mallcop-selfext"
	contribCommitEmail = "selfext@mallcop.app"
)

// pushContribBranch is the missing step mallcoppro-a6c's veracity rework
// found: nothing in the selfext path ever created, committed to, or pushed
// contribback/<fingerprint> before `gh pr create` was called, so `gh pr
// create` failed 100% of the time in production ("Head sha can't be blank",
// "No commits between main and contribback/...", "Head ref must be a
// branch"). This function must run — and succeed — before
// contribback.Opener.Contribute (which calls PROpener.OpenPR) for every
// artifact `mallcop selfext --contribute` attempts.
//
// It clones cloneSpec (production: an https://github.com/<owner>/<repo>.git
// URL, resolved through the operator's own `gh`-configured git credential
// helper — `gh auth login` wires this up for github.com; NO token is ever
// read or set into the child environment here, design ruling R8 — a plain
// local filesystem path is equally valid input to `git clone`, which is what
// the test suite uses to exercise this EXACT code against a real bare repo
// with no network involved), checks out art.HeadBranch() as a NEW branch,
// writes the artifact's own JSON to a staging path under contrib-back/ (see
// stagingArtifactFile — the reviewable content a maintainer reads alongside
// the PR title/body; this deliberately does NOT compute or apply the actual
// widen into the OSS repo's own detectors/tuning.yaml /
// learned_mappings.yaml — landing it is the maintainer's reviewed merge
// decision, design rulings R3/R8), commits it, and force-pushes the branch to
// origin.
//
// Force-push is safe here: contribback/<fingerprint> is a deterministic name
// this automation exclusively owns and regenerates byte-for-byte on every
// re-run, so a retry after a partial failure (e.g. a prior run pushed the
// branch but OpenPR then errored) must not fail on a stale non-fast-forward
// against its own earlier attempt.
//
// It returns an error — never silently succeeds — on any step that does not
// leave a real, pushed commit on the branch: an unreachable clone target, a
// failed checkout, a failed write, a failed commit, or a failed push all
// abort here, before Contribute (and therefore PROpener.OpenPR) is ever
// called.
func pushContribBranch(ctx context.Context, cloneSpec, baseBranch string, art contribback.Artifact) error {
	if strings.TrimSpace(cloneSpec) == "" {
		return fmt.Errorf("contribute: push head branch: clone target is empty")
	}
	relPath, content, err := stagingArtifactFile(art)
	if err != nil {
		return fmt.Errorf("contribute: push head branch: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "mallcop-contribback-*")
	if err != nil {
		return fmt.Errorf("contribute: push head branch: scratch dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	run := func(dir, name string, args ...string) error {
		out, rerr := contribPushRunner(ctx, dir, name, args...)
		if rerr != nil {
			return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), rerr, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("", "git", "clone", "--quiet", cloneSpec, tmpDir); err != nil {
		return fmt.Errorf("contribute: push head branch: clone %s: %w", cloneSpec, err)
	}
	// Check out the PR's actual base explicitly rather than trusting the
	// clone's default HEAD to already be it (it usually is, but the branch
	// this PR opens against — Config.BaseBranch/baseBranch() — is the
	// authoritative source of truth, not an assumption about clone defaults).
	if err := run(tmpDir, "git", "checkout", "-q", baseBranch); err != nil {
		return fmt.Errorf("contribute: push head branch: checkout base %s: %w", baseBranch, err)
	}

	head := art.HeadBranch()
	if err := run(tmpDir, "git", "checkout", "-q", "-b", head); err != nil {
		return fmt.Errorf("contribute: push head branch: checkout -b %s: %w", head, err)
	}

	fullPath := filepath.Join(tmpDir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return fmt.Errorf("contribute: push head branch: mkdir %s: %w", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, content, 0o644); err != nil {
		return fmt.Errorf("contribute: push head branch: write %s: %w", relPath, err)
	}
	if err := run(tmpDir, "git", "add", relPath); err != nil {
		return fmt.Errorf("contribute: push head branch: git add %s: %w", relPath, err)
	}

	msg := art.Title
	if strings.TrimSpace(art.Body) != "" {
		msg = msg + "\n\n" + art.Body
	}
	if err := run(tmpDir, "git",
		"-c", "user.name="+contribCommitName,
		"-c", "user.email="+contribCommitEmail,
		"-c", "commit.gpgsign=false",
		"commit", "-q", "-m", msg,
	); err != nil {
		return fmt.Errorf("contribute: push head branch: git commit: %w", err)
	}

	if err := run(tmpDir, "git", "push", "--force", "--quiet", "origin", head+":"+head); err != nil {
		return fmt.Errorf("contribute: push head branch: git push %s: %w", head, err)
	}
	return nil
}

// stagingArtifactFile returns the repo-relative path and JSON content
// pushContribBranch commits onto a contribute-back PR's head branch: a
// machine-readable copy of the artifact the PR proposes, for the OSS
// maintainer to review alongside the PR title/body. It deliberately does NOT
// attempt to compute or apply the actual widen into the OSS repo's own
// detectors/tuning.yaml / learned_mappings.yaml — landing the widen is the
// maintainer's reviewed merge decision (design rulings R3/R8); this stages
// the proposal for that review, it does not pre-empt it.
func stagingArtifactFile(art contribback.Artifact) (relPath string, content []byte, err error) {
	fp := strings.TrimSpace(art.Fingerprint)
	if fp == "" {
		fp = "nofp"
	}
	rel := filepath.ToSlash(filepath.Join("contrib-back", sanitizeForFilename(fp)+".json"))
	data, merr := json.MarshalIndent(art, "", "  ")
	if merr != nil {
		return "", nil, fmt.Errorf("marshal artifact for staging: %w", merr)
	}
	return rel, data, nil
}

// sanitizeForFilename keeps a fingerprint filename-safe: only
// alphanumerics/-/_ survive, everything else becomes '_'.
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
