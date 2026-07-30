// poll.go closes the OTHER half of the contribute-back loop: dispatches stop
// being fire-and-forget by having a LATER scan ask whether an already-opened
// shared-OSS PR merged or closed.
//
// # THIS IS A POLL, NOT A WEBHOOK
//
// An earlier design specified an inbound GitHub webhook (X-Hub-Signature-256
// verification, a provisioned shared secret, a new authenticated HTTP
// receiver in mallcop-pro). That design was WITHDRAWN 2026-07-30: the
// contribute-back PR is opened under the OPERATOR's own `gh` identity against
// the SHARED repo (gh_opener.go, design ruling R8 — mallcop holds no standing
// write credential there), so it is NOT in the customer's own repo and the
// customer's GHA run has no native event to receive for it. A webhook would
// also buy seconds-latency on an event that takes DAYS (a maintainer review),
// at the cost of a shared secret, an authenticated public endpoint, HMAC
// verification, replay/nonce handling, and delivery-id idempotency.
//
// Instead: the shared repo is PUBLIC. PollOutcomes asks GitHub's public REST
// API for a PR's state — no credential, no secret, no inbound endpoint, ever.
package contribback

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
)

// defaultGitHubAPIBase is GitHub's real public REST API. Overridable (via
// NewGitHubFetcher's argument) so a test can point at a local httptest.Server
// instead — the override is a URL, never a credential.
const defaultGitHubAPIBase = "https://api.github.com"

// PRState is a fetched pull request's live state, as GitHub's REST API
// reports it (GET /repos/<owner>/<repo>/pulls/<number>).
type PRState struct {
	// State is GitHub's own vocabulary: "open" or "closed". A merged PR is
	// ALSO reported "closed" by GitHub — Merged is what disambiguates it.
	State string
	// Merged is true iff the PR was merged (only meaningful when State is
	// "closed").
	Merged bool
}

// PRStateFetcher fetches ONE pull request's live state. The production
// implementation (githubFetcher) is an UNAUTHENTICATED GET against GitHub's
// public REST API — the shared OSS repo is public, so reading a PR's state
// needs no credential, no secret, no token, ever.
type PRStateFetcher interface {
	FetchPRState(ctx context.Context, owner, repo string, number int) (PRState, error)
}

// githubFetcher is the production PRStateFetcher.
type githubFetcher struct {
	apiBase string
	client  *http.Client
}

// NewGitHubFetcher returns a PRStateFetcher that reads a pull request's state
// from GitHub's public REST API, UNAUTHENTICATED — it never reads, sends, or
// stores any credential. apiBase empty defaults to the real GitHub API
// (https://api.github.com); a test overrides it to point at a local
// httptest.Server so the real HTTP round trip never touches the network.
func NewGitHubFetcher(apiBase string) PRStateFetcher {
	if strings.TrimSpace(apiBase) == "" {
		apiBase = defaultGitHubAPIBase
	}
	return &githubFetcher{
		apiBase: strings.TrimRight(apiBase, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *githubFetcher) FetchPRState(ctx context.Context, owner, repo string, number int) (PRState, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d", g.apiBase, owner, repo, number)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PRState{}, fmt.Errorf("contribback: build PR-state request: %w", err)
	}
	// Accept header only — deliberately NO Authorization header. The shared
	// repo is public; this call authenticates as nobody.
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client.Do(req)
	if err != nil {
		return PRState{}, fmt.Errorf("contribback: fetch PR state %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return PRState{}, fmt.Errorf("contribback: GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	var payload struct {
		State  string `json:"state"`
		Merged bool   `json:"merged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return PRState{}, fmt.Errorf("contribback: decode PR-state response from %s: %w", url, err)
	}
	return PRState{State: payload.State, Merged: payload.Merged}, nil
}

// prURLPattern matches exactly "https://github.com/<owner>/<repo>/pull/<n>" —
// no query string, no fragment, no trailing slash. Strict on purpose: see
// ParsePRURL.
var prURLPattern = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/pull/(\d+)$`)

// ParsePRURL extracts (owner, repo, number) from a github.com pull-request
// URL. It is deliberately strict, and deliberately the ONLY way PollOutcomes
// decides which repo/PR to read: a persisted ContribBackRecord's URL is the
// sole source of truth — mallcoppro-003 requires this explicitly ("Parse the
// owner/repo/number from the persisted URL — do not re-derive the repo from
// config") precisely so an operator's OWN opened PR is what gets read, never
// a config value or any other input. A record's URL can only ever have been
// written by this operator's own OpenPR call (Store.Append requires a local
// git-commit write), so there is no path for an attacker-supplied URL to
// reach this function at all — but ParsePRURL is strict regardless, and
// rejects anything that isn't this exact shape rather than guessing.
func ParsePRURL(url string) (owner, repo string, number int, err error) {
	m := prURLPattern.FindStringSubmatch(strings.TrimSpace(url))
	if m == nil {
		return "", "", 0, fmt.Errorf("contribback: %q is not a github.com pull-request URL", url)
	}
	n, convErr := strconv.Atoi(m[3])
	if convErr != nil {
		return "", "", 0, fmt.Errorf("contribback: %q has a non-numeric PR number: %w", url, convErr)
	}
	return m[1], m[2], n, nil
}

// PollSummary tallies what one PollOutcomes call did, for the caller (`mallcop
// scan`) to log without treating any of it as fatal.
type PollSummary struct {
	// Considered is how many contribback records were still State=="open"
	// (the only ones a poll ever looks at).
	Considered int
	// Updated is how many of those had their state change (merged/closed) —
	// each is one fresh appended row.
	Updated int
	// Failed is how many fetches did not succeed (network failure, PR
	// deleted/404, rate-limited, or a record whose URL failed to parse). Each
	// is left EXACTLY as it was — no fabricated outcome.
	Failed int
}

// PollOutcomes reads the contribback stream off s, folds it to the LATEST row
// per PRURL (mirrors the mallcoppro-42e keyed-record discipline: only the
// most recent row per key is "live"), and for every record still
// State==ContribBackOpen asks fetch for that PR's current state:
//
//   - merged           -> a FRESH row is appended, State -> ContribBackMerged.
//   - closed, unmerged  -> a FRESH row is appended, State -> ContribBackClosed.
//   - still open, OR the fetch failed (network down, PR deleted/404, rate
//     limited, unparseable URL) -> NOTHING is appended: no fabricated state,
//     no duplicate no-op row, no re-scan churn (the same mallcoppro-42e
//     discipline again).
//
// PollOutcomes returns a non-nil error ONLY when reading or appending to the
// store itself fails. Individual PR-fetch failures are tallied in
// Summary.Failed and NEVER surface as a returned error — a scan that
// otherwise succeeded must never fail because a public API on the far side of
// the network was briefly unreachable, or because a contribution's PR was
// deleted.
func PollOutcomes(ctx context.Context, s *store.Store, fetch PRStateFetcher) (PollSummary, error) {
	var sum PollSummary
	if s == nil || fetch == nil {
		return sum, nil
	}
	recs, err := s.LoadContribBackRecords()
	if err != nil {
		return sum, fmt.Errorf("contribback: load contribback stream: %w", err)
	}
	for _, rec := range latestByURL(recs) {
		if rec.State != store.ContribBackOpen {
			continue
		}
		sum.Considered++

		owner, repo, number, perr := ParsePRURL(rec.PRURL)
		if perr != nil {
			// A malformed URL is a data problem, not a network one — but the
			// contract is identical either way: degrade honestly, never
			// fabricate, move on.
			sum.Failed++
			continue
		}

		state, ferr := fetch.FetchPRState(ctx, owner, repo, number)
		if ferr != nil {
			sum.Failed++
			continue
		}

		newState := store.ContribBackOpen
		switch {
		case state.Merged:
			newState = store.ContribBackMerged
		case state.State == "closed":
			newState = store.ContribBackClosed
		}
		if newState == rec.State {
			// No change observed — append nothing (idempotent: no churn).
			continue
		}

		updated := rec
		updated.State = newState
		updated.UpdatedAt = time.Now().UTC()
		if _, aerr := s.Append(store.KindContribBack, updated); aerr != nil {
			return sum, fmt.Errorf("contribback: append updated outcome for %s: %w", rec.PRURL, aerr)
		}
		sum.Updated++
	}
	return sum, nil
}

// latestByURL folds a contribback stream (oldest-first, as
// LoadContribBackRecords returns it) down to one record per PRURL: the most
// recently appended row for that URL wins. This mirrors the case-keyed
// "latest row per key" discipline mallcoppro-42e established for
// investigation records — a state-change row supersedes every earlier row
// for the same PR without ever mutating them in place.
func latestByURL(recs []store.ContribBackRecord) []store.ContribBackRecord {
	order := make([]string, 0, len(recs))
	byURL := make(map[string]store.ContribBackRecord, len(recs))
	for _, r := range recs {
		if _, ok := byURL[r.PRURL]; !ok {
			order = append(order, r.PRURL)
		}
		byURL[r.PRURL] = r
	}
	out := make([]store.ContribBackRecord, 0, len(order))
	for _, u := range order {
		out = append(out, byURL[u])
	}
	return out
}
