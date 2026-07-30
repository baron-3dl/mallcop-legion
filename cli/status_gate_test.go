package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
)

// TestEvaluateLiveness_Unit proves the pure gate-decision logic in isolation:
// legacy-record classification, staleness, and genuine failure. This is a
// unit test on evaluateLiveness itself, distinct from the integration tests
// below that exercise it through the real CLI entrypoint and a real
// git-backed store.
func TestEvaluateLiveness_Unit(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	maxAge := 48 * time.Hour

	cases := []struct {
		name        string
		scans       []store.ScanRecord
		wantHealthy bool
	}{
		{
			name:        "no history at all is unhealthy",
			scans:       nil,
			wantHealthy: false,
		},
		{
			name: "fresh success is healthy",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-time.Hour), FinishedAt: now.Add(-time.Minute), Success: true},
			},
			wantHealthy: true,
		},
		{
			name: "genuine failure (FailedStage+Error populated) is unhealthy regardless of age",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-time.Minute), FinishedAt: now, Success: false, FailedStage: "connect", Error: "403 forbidden"},
			},
			wantHealthy: false,
		},
		{
			name: "stale success (older than max-age) is unhealthy",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-72 * time.Hour), FinishedAt: now.Add(-49 * time.Hour), Success: true},
			},
			wantHealthy: false,
		},
		{
			name: "legacy record (Success=false, FailedStage=='', Error=='') predating mallcoppro-24e is treated as completed, not failed",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-time.Hour), FinishedAt: now.Add(-time.Minute)}, // zero-value Success/FailedStage/Error
			},
			wantHealthy: true,
		},
		{
			name: "stale legacy record still fails on age",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-72 * time.Hour), FinishedAt: now.Add(-49 * time.Hour)}, // legacy shape, but stale
			},
			wantHealthy: false,
		},
		{
			name: "only the NEWEST (last) record is evaluated — an old failure behind a fresh success is healthy",
			scans: []store.ScanRecord{
				{StartedAt: now.Add(-3 * time.Hour), FinishedAt: now.Add(-2 * time.Hour), Success: false, FailedStage: "connect", Error: "403"},
				{StartedAt: now.Add(-time.Hour), FinishedAt: now.Add(-time.Minute), Success: true},
			},
			wantHealthy: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateLiveness(tc.scans, maxAge, now)
			if got.Healthy != tc.wantHealthy {
				t.Fatalf("evaluateLiveness() = %+v, want Healthy=%v", got, tc.wantHealthy)
			}
			if !got.Healthy && got.Reason == "" {
				t.Fatalf("unhealthy result must carry a Reason, got %+v", got)
			}
		})
	}
}

// seedScan appends a store.ScanRecord directly onto the REAL git-backed
// store's KindScans stream via st.Append — the same path
// core/pipeline.recordScan uses in production. Not a mock: this is the
// actual store.Store.Append/Load round trip through real git commits (see
// initStatusRepo in status_test.go for the underlying git-init helper).
func seedScan(t *testing.T, st *store.Store, rec store.ScanRecord) {
	t.Helper()
	if _, err := st.Append(store.KindScans, rec); err != nil {
		t.Fatalf("seed ScanRecord: %v", err)
	}
}

// TestRunStatusGate_RejectsStaleOrFailedHistory is the ENFORCEMENT-BUNDLE
// "rejects" half (mallcoppro-1e0 acceptance): given a KindScans history whose
// newest record is either >48h old or Success=false, `mallcop status --gate
// --max-age 48h` must exit nonzero (the errFindings sentinel main.go maps to
// exit code 1). Exercises the REAL CLI entrypoint (runStatus) over a REAL
// git-backed store.Store — not a mock of either.
func TestRunStatusGate_RejectsStaleOrFailedHistory(t *testing.T) {
	t.Run("failed newest record", func(t *testing.T) {
		repo := initStatusRepo(t)
		st, err := store.Open(repo)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		seedScan(t, st, store.ScanRecord{
			StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(),
			Success: false, FailedStage: "connect", Error: "403 forbidden",
		})

		var out bytes.Buffer
		err = runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate", "--max-age", "48h"})
		if err == nil {
			t.Fatalf("runStatus: expected a nonzero-exit error for a failed newest scan, got nil.\noutput:\n%s", out.String())
		}
		if !isFindingsError(err) {
			t.Fatalf("runStatus: expected the errFindings sentinel, got %v (type %T)", err, err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Liveness:   FAIL")) {
			t.Fatalf("expected a Liveness FAIL line, got:\n%s", out.String())
		}
	})

	t.Run("stale newest record", func(t *testing.T) {
		repo := initStatusRepo(t)
		st, err := store.Open(repo)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		old := time.Now().Add(-72 * time.Hour)
		seedScan(t, st, store.ScanRecord{
			StartedAt: old, FinishedAt: old.Add(time.Minute), Success: true,
		})

		var out bytes.Buffer
		err = runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate", "--max-age", "48h"})
		if err == nil {
			t.Fatalf("runStatus: expected a nonzero-exit error for a stale newest scan, got nil.\noutput:\n%s", out.String())
		}
		if !isFindingsError(err) {
			t.Fatalf("runStatus: expected the errFindings sentinel, got %v (type %T)", err, err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Liveness:   FAIL")) {
			t.Fatalf("expected a Liveness FAIL line, got:\n%s", out.String())
		}
	})

	t.Run("no scan history at all", func(t *testing.T) {
		repo := initStatusRepo(t)
		// No KindScans records appended at all.

		var out bytes.Buffer
		err := runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate", "--max-age", "48h"})
		if err == nil {
			t.Fatalf("runStatus: expected a nonzero-exit error for an empty scan history, got nil.\noutput:\n%s", out.String())
		}
		if !isFindingsError(err) {
			t.Fatalf("runStatus: expected the errFindings sentinel, got %v (type %T)", err, err)
		}
	})

	t.Run("uninitialized store (no .git at all)", func(t *testing.T) {
		dir := t.TempDir() // never git-init'd

		var out bytes.Buffer
		err := runStatusCapturing(t, &out, []string{"--store", dir, "--gate", "--max-age", "48h"})
		if err == nil {
			t.Fatalf("runStatus: expected a nonzero-exit error for an uninitialized store under --gate, got nil.\noutput:\n%s", out.String())
		}
		if !isFindingsError(err) {
			t.Fatalf("runStatus: expected the errFindings sentinel, got %v (type %T)", err, err)
		}
	})
}

// TestRunStatusGate_AllowsFreshHealthyHistory is the ENFORCEMENT-BUNDLE
// "allows" half (mallcoppro-1e0 acceptance): given a fresh healthy history,
// `mallcop status --gate --max-age 48h` must exit zero. Same REAL CLI
// entrypoint and REAL git-backed store as the rejects test above.
func TestRunStatusGate_AllowsFreshHealthyHistory(t *testing.T) {
	repo := initStatusRepo(t)
	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seedScan(t, st, store.ScanRecord{
		StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(),
		Success: true, EventsScanned: 4, FindingsDetected: 1,
	})

	var out bytes.Buffer
	err = runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate", "--max-age", "48h"})
	if err != nil {
		t.Fatalf("runStatus: expected a nil (exit 0) result for a fresh healthy history, got %v.\noutput:\n%s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("Liveness:   OK")) {
		t.Fatalf("expected a Liveness OK line, got:\n%s", out.String())
	}
}

// TestRunStatusGate_LegacyRecordNotMisreadAsFailure is the CAUTION item from
// the mallcoppro-1e0 dispatch (tracked mallcoppro-3c7): a ScanRecord written
// BEFORE mallcoppro-24e decodes with Success=false via Go's JSON zero-value —
// indistinguishable at the field level from a genuine failure with an empty
// stage/error. The gate must treat FailedStage=="" AND Error=="" as
// legacy-completed, not failed, so a store whose entire history predates
// mallcoppro-24e is not misread as an all-failing pipeline.
func TestRunStatusGate_LegacyRecordNotMisreadAsFailure(t *testing.T) {
	repo := initStatusRepo(t)
	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	// Simulates a pre-mallcoppro-24e binary's append: only the fields that
	// existed before Success/FailedStage/Error were added.
	seedScan(t, st, store.ScanRecord{
		StartedAt:     time.Now().Add(-time.Minute),
		FinishedAt:    time.Now(),
		EventsScanned: 10,
		// Success, FailedStage, Error all left at zero value on purpose.
	})

	var out bytes.Buffer
	err = runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate", "--max-age", "48h"})
	if err != nil {
		t.Fatalf("runStatus: a legacy-completed record must NOT gate-fail as if it were a real failure; got %v.\noutput:\n%s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("Liveness:   OK")) {
		t.Fatalf("expected a Liveness OK line for a legacy-completed record, got:\n%s", out.String())
	}
}

// runStatusCapturing runs runStatus with os.Stdout redirected into out, the
// same real-stdout-capture technique status_test.go's captureStdout uses
// (kept separate here so it can also return runStatus's error, which
// captureStdout's void-callback signature does not support).
func runStatusCapturing(t *testing.T, out *bytes.Buffer, args []string) error {
	t.Helper()
	var runErr error
	captured := captureStdout(t, func() {
		runErr = runStatus(args)
	})
	if _, err := out.WriteString(captured); err != nil {
		t.Fatalf("buffering captured stdout: %v", err)
	}
	return runErr
}

// TestRunStatusGate_UnhealthyErrorIsFindingsSentinel guards the exit-code
// contract main.go depends on: a gate failure must be the *findingsError
// sentinel (exit 1), never a generic error (which main.go maps to exit 2).
// A future refactor that swaps errFindings for fmt.Errorf would silently
// change the customer's job exit code from "findings/gate" (1) to "hard
// failure" (2) without any test failing elsewhere.
func TestRunStatusGate_UnhealthyErrorIsFindingsSentinel(t *testing.T) {
	repo := initStatusRepo(t)
	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seedScan(t, st, store.ScanRecord{
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Success: false, FailedStage: "connect", Error: "403",
	})

	var out bytes.Buffer
	gotErr := runStatusCapturing(t, &out, []string{"--store", filepath.Clean(repo), "--gate"})
	if !errors.Is(gotErr, errFindings) && !isFindingsError(gotErr) {
		t.Fatalf("expected errFindings sentinel (or an error satisfying isFindingsError), got %v", gotErr)
	}
}
