// Package contribback opens the SECOND pull request in mallcop's self-extension
// loop. After a customer's OWN gated PR merges into their thin-embed repo, an
// OPTIONALLY-consented, universally-applicable widen may be proposed BACK to the
// shared OSS corpus (mallcop-app/mallcop) as a pull request the OSS project's own
// CI (exam.yml) and CODEOWNERS review gate. The router (the router package)
// already decides WHICH widens are OSS-eligible and emits a reviewable OSS-PR
// artifact for each; this package is the step that (opt-in) turns that artifact
// into an actual pull request.
//
// # Three hard invariants — none dial-overridable
//
//  1. OFF BY DEFAULT. The zero-value Config is disabled. Contribute-back never
//     runs unless the operator EXPLICITLY opts in (Config.Enabled). Building the
//     Opener, wiring the router, or handing it an artifact changes nothing on its
//     own — silence is the default.
//
//  2. OPERATOR IDENTITY, NO STANDING CREDENTIAL (design ruling R8). The PR is
//     opened under the OPERATOR's own gh credential, resolved at call time from
//     their ambient environment. The operator binary stores no machine-bot token
//     and holds no standing write credential to the shared repo. The Opener never
//     accepts, persists, or logs a token; PROpener implementations authenticate
//     entirely out-of-band (the operator's `gh auth`).
//
//  3. NEVER AUTO-MERGES AT ANY DIAL (design ruling R3, the contribute-back hard
//     line). This package has NO merge path — not a disabled one, not a
//     dial-gated one: none exists. The autonomy dial is accepted by Contribute
//     ONLY so the invariant is explicit and testable: every tier, INCLUDING the
//     most-autonomous "fully"/yolo setting, opens the PR and stops. Merging the
//     shared-OSS PR is the OSS maintainers' job, gated by OSS CI + review — it is
//     categorically outside this process's hands.
package contribback

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
)

// Config is the operator-owned, opt-in contribute-back configuration. The
// ZERO VALUE is DISABLED (Enabled == false): contribute-back is off until the
// operator turns it on. This is distinct from a customer's per-widen consent
// (which the router already enforces before it ever emits an OSS artifact) —
// Config.Enabled is the operator's standing opt-in for THIS operator
// deployment to open shared-OSS PRs at all.
type Config struct {
	// Enabled is the opt-in switch. False (the zero value) = contribute-back
	// disabled; no shared-OSS PR is ever opened.
	Enabled bool
	// Repo is the shared OSS repository, "owner/name" (e.g. "mallcop-app/mallcop").
	// Required when Enabled.
	Repo string
	// BaseBranch is the PR's target branch on the shared repo. Empty defaults to
	// "main".
	BaseBranch string
}

func (c Config) baseBranch() string {
	if strings.TrimSpace(c.BaseBranch) == "" {
		return "main"
	}
	return c.BaseBranch
}

// Lane discriminates the two contribute-back lanes an Artifact can carry.
//
//   - LaneData: a mapping/tuning WIDEN of an existing detector/connector (the
//     PRIMARY data lane). LoadArtifact distills this from the router's oss-pr-*.json.
//   - LaneCode: a promoted AUTHORED DETECTOR — a merged customer-repo
//     detectors/<name>/ (source + scenarios) proposed for promotion into OSS
//     core/detect/authored/<name>/ (the gated code escape hatch). LoadCodeArtifact
//     distills this. This is the lane flagged as missing: the DATA
//     lane emitted a reviewable artifact but a merged authored detector had none, so
//     a human had to hand-build the upstream PR.
type Lane string

const (
	// LaneData is the mapping/tuning widen lane (the zero value — back-compat with
	// the original LoadArtifact, which predates the Lane field and never set it).
	LaneData Lane = "data"
	// LaneCode is the authored-detector promotion lane.
	LaneCode Lane = "code"
)

// PromotedFile maps ONE authored-detector file from its path in the customer's
// thin-embed repo to its destination in the shared OSS repo. Code lane only.
type PromotedFile struct {
	// Src is the file's path in the customer repo (e.g.
	// "detectors/deploy-burst/detector.go").
	Src string
	// Dest is the file's path in the OSS repo (e.g.
	// "core/detect/authored/deploy-burst/detector.go").
	Dest string
}

// Artifact is the OSS contribute-back proposal handed to the Opener — the
// distilled content of the router's emitted OSS-PR artifact. It carries the widen
// and the two eligibility facts the router already established (the customer
// consented to this build; the widen is universally applicable), plus the PR
// content. It holds NO credential.
type Artifact struct {
	// Lane is which contribute-back lane produced this artifact. The zero value
	// ("") means LaneData — LoadArtifact predates this field and never sets it, so
	// existing DATA-lane callers keep working unchanged.
	Lane Lane
	// Fingerprint of the originating gap — used to name the head branch so a
	// re-run for the same widen is idempotent (one open PR per fingerprint).
	Fingerprint string
	// Consented records that the customer consented to OSS contribute-back for the
	// build this widen came from. The router only emits an OSS artifact when this
	// is true; it is re-checked here as defense in depth.
	Consented bool
	// Universal records that the widen is universally applicable (not
	// tenant-specific). The router only emits an OSS artifact when this is true;
	// re-checked here as defense in depth. A non-universal widen is never
	// contributed.
	Universal bool
	// DetectorName is the authored detector's name (LaneCode only). It names the
	// OSS destination package core/detect/authored/<DetectorName>/.
	DetectorName string
	// Files is the ordered file set this artifact promotes (LaneCode only): each
	// entry maps a customer-repo source path to its OSS-repo destination path.
	// Empty for the data lane.
	Files []PromotedFile
	// GateRef references the gate result that certified this proposal (a gate
	// artifact id or the gate run's head SHA) — provenance for the PR body's audit
	// trail, so a reviewer can trace the promotion back to the exact gate that
	// GREEN-certified it. Never a credential.
	GateRef string
	// Title is the PR title.
	Title string
	// Body is the PR body (markdown). It should describe the widen, cite the
	// originating gap fingerprint, and note that OSS CI + CODEOWNERS review gate
	// the merge.
	Body string
}

// HeadBranch is the deterministic head-branch name for this artifact's PR:
// "contribback/<short-fingerprint>". Deterministic naming makes re-running the
// same widen idempotent rather than opening a duplicate PR.
func (a Artifact) HeadBranch() string {
	fp := strings.TrimSpace(a.Fingerprint)
	if fp == "" {
		return "contribback/nofp"
	}
	if len(fp) > 12 {
		fp = fp[:12]
	}
	return "contribback/" + fp
}

// PRRequest is the content of a shared-OSS pull request. It carries NO
// credential — the PROpener authenticates out-of-band under the operator's
// identity.
type PRRequest struct {
	Repo       string
	BaseBranch string
	HeadBranch string
	Title      string
	Body       string
}

// PRResult is what an opened pull request reports back.
type PRResult struct {
	// URL of the opened pull request.
	URL string
}

// PROpener opens a pull request under the OPERATOR's identity and returns it.
//
// The interface exposes NO merge operation — merging the shared-OSS PR is
// categorically out of this process's hands (design rulings R3/R8), so there is
// nothing here that any dial could unlock. Implementations MUST authenticate as
// the operator via their ambient credential (their `gh auth`); they MUST NOT
// accept or store a standing write credential. The production implementation
// (ghOpener) shells out to `gh pr create`.
type PROpener interface {
	OpenPR(ctx context.Context, req PRRequest) (PRResult, error)
}

// Outcome records what Contribute did for one artifact.
type Outcome struct {
	// Attempted is true when contribute-back was enabled AND the artifact was
	// eligible, so an OpenPR call was made.
	Attempted bool
	// Opened is true when a shared-OSS PR was successfully opened. When true the
	// PR is OPEN and unmerged — always, at every dial.
	Opened bool
	// PRURL is the opened PR's URL (set iff Opened).
	PRURL string
	// SkipReason is set (and Attempted/Opened false) when contribute-back did not
	// run: disabled, not consented, or not universal.
	SkipReason string
}

// Opener opens shared-OSS contribute-back PRs. It never merges.
type Opener struct {
	// Config is the operator's opt-in configuration. Zero value = disabled.
	Config Config
	// PR is the injected PR opener (real = ghOpener under operator identity).
	// Required when Config.Enabled.
	PR PROpener
	// Store is the operator's own git-backed store. Required when
	// Config.Enabled: the moment a shared-OSS PR opens, Contribute appends a
	// ContribBackRecord (State=open) to store.KindContribBack through this
	// handle — this is the ONLY place that record is ever written, and
	// without it a later scan's selfext/contribback.PollOutcomes has nothing
	// to poll (mallcoppro-003 veracity rework: OpenPR returning a URL is not
	// the same as persisting it).
	Store *store.Store
	// Logger receives non-secret events. Nil → discard.
	Logger *slog.Logger
}

func (o *Opener) logger() *slog.Logger {
	if o.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return o.Logger
}

// Contribute opens the shared-OSS PR for art IF contribute-back is enabled and
// the artifact is eligible (consented + universal). It returns the Outcome.
//
// The dial parameter is accepted ONLY to make the hard line explicit and
// testable: it is NEVER read to decide behavior. No dial value — not even the
// most-autonomous "fully"/yolo setting — changes what happens, because this
// method has no merge path: on success the PR is left OPEN for OSS CI +
// maintainer review, at EVERY dial. Passing the dial in (rather than ignoring it
// entirely) lets tests assert the invariant across the whole dial range.
func (o *Opener) Contribute(ctx context.Context, dial autonomy.Dial, art Artifact) (Outcome, error) {
	// (1) OPT-IN, OFF BY DEFAULT. The zero-value Config is disabled.
	if !o.Config.Enabled {
		return Outcome{SkipReason: "contribute-back disabled (opt-in; off by default)"}, nil
	}
	// (2) Eligibility — re-checked as defense in depth even though the router only
	//     emits artifacts that already satisfy both.
	if !art.Consented {
		return Outcome{SkipReason: "no shared-OSS PR: customer did not consent to contribute-back"}, nil
	}
	if !art.Universal {
		return Outcome{SkipReason: "no shared-OSS PR: widen is tenant-specific, not universally applicable"}, nil
	}
	if o.PR == nil {
		return Outcome{}, errors.New("contribback: PR opener is nil (enabled but not wired)")
	}
	if o.Store == nil {
		return Outcome{}, errors.New("contribback: store is nil (enabled but not wired) -- required to persist the opened PR so a later scan can poll its outcome")
	}
	if strings.TrimSpace(o.Config.Repo) == "" {
		return Outcome{}, errors.New("contribback: Config.Repo is empty (enabled but no target repo)")
	}

	req := PRRequest{
		Repo:       o.Config.Repo,
		BaseBranch: o.Config.baseBranch(),
		HeadBranch: art.HeadBranch(),
		Title:      art.Title,
		Body:       art.Body,
	}
	res, err := o.PR.OpenPR(ctx, req)
	if err != nil {
		return Outcome{Attempted: true}, fmt.Errorf("contribback: open shared-OSS PR: %w", err)
	}

	// PERSIST IMMEDIATELY. Returning res.URL to the caller is not enough — the
	// contribback stream is the ONLY thing a later scan's PollOutcomes reads,
	// so if this Append never happens the PR is opened-and-forgotten: no
	// outcome ever flows back (mallcoppro-003 veracity rework). This is a
	// fresh row, never a mutation, mirroring the KindGrants/KindScans
	// append-only discipline every other stream uses.
	now := time.Now().UTC()
	rec := store.ContribBackRecord{
		Fingerprint: art.Fingerprint,
		PRURL:       res.URL,
		State:       store.ContribBackOpen,
		OpenedAt:    now,
		UpdatedAt:   now,
	}
	if _, aerr := o.Store.Append(store.KindContribBack, rec); aerr != nil {
		// The PR is already open on GitHub and cannot be un-opened here — but a
		// failure to persist the record is a real defect (the PR becomes
		// unpollable), so it is reported as an error rather than swallowed.
		return Outcome{Attempted: true, Opened: true, PRURL: res.URL},
			fmt.Errorf("contribback: opened %s but failed to persist its contribback record: %w", res.URL, aerr)
	}

	// The dial is deliberately NOT consulted, and there is deliberately NO merge
	// call here or anywhere in this package. The PR is left OPEN for OSS CI +
	// maintainer review — always, at every dial including "fully"/yolo. This log
	// line records the dial only for provenance, to make it auditable that the PR
	// was opened-not-merged regardless of the dial in force.
	o.logger().Info("contribback: opened shared-OSS PR (never merged — OSS CI + maintainer review gates it)",
		"repo", req.Repo, "head", req.HeadBranch, "dial", dial.Normalized(), "url", res.URL)

	return Outcome{Attempted: true, Opened: true, PRURL: res.URL}, nil
}
