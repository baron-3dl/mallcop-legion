package pipeline_test

// scanrecord_failure_test.go — the REGRESSION coverage for mallcoppro-24e
// (design §5, "the reinforcing bug"): a connector Pull failure (the ground-
// truth case is a 403-on-connect) used to return BEFORE recordScan ever
// fired, so the store's scans stream went dark exactly when the liveness
// watchdog needed the signal most. The fix makes recordScan a deferred call
// driven by Run's named returns, so EVERY return from Run — success or
// failure, at ANY stage — commits exactly one store.ScanRecord.
//
// This drives the REAL pipeline.Run entry point (not a unit test on
// recordScan in isolation) against a REAL temp git store, exactly the way
// TestPipeline_EndToEnd_ConnectDetectCascadeStore does, and reads the result
// back through the real store.LoadScans.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// forbiddenConnector.Pull always fails the way a connector hitting an
// unauthorized/expired-credential source does — a 403 from the remote API.
// It carries no events; a connect-stage failure aborts before detect ever
// runs, so there is nothing to pull.
type forbiddenConnector struct{}

func (forbiddenConnector) Pull(_ context.Context) ([]event.Event, error) {
	return nil, errors.New("github: GET /orgs/atom/audit-log: 403 Forbidden (token revoked)")
}

// TestPipeline_ConnectorPullFailure_StillRecordsScan is the headline
// regression: a connector Pull failure must NOT leave the scans stream
// silent. Before the fix, Run returned at the connect error BEFORE recordScan
// fired, and store.LoadScans() came back empty after this exact scenario.
func TestPipeline_ConnectorPullFailure_StillRecordsScan(t *testing.T) {
	st := newGitStore(t)

	cfg := pipeline.Config{
		Connector: forbiddenConnector{},
		Client:    &inference.DirectClient{BaseURL: "http://unused.invalid", Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err == nil {
		t.Fatalf("pipeline.Run over a Pull-failing connector returned nil error; want the wrapped connect error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Run error = %q, want it to carry the underlying 403", err.Error())
	}
	if sum.EventsScanned != 0 {
		t.Errorf("Summary on a connect failure = %+v, want the zero Summary", sum)
	}

	scans, lerr := st.LoadScans()
	if lerr != nil {
		t.Fatalf("LoadScans: %v", lerr)
	}
	// THE bug this item fixes: before the fix, this was 0 — the connect
	// failure returned before recordScan ever ran.
	if len(scans) != 1 {
		t.Fatalf("LoadScans returned %d records after a connector Pull failure, want exactly 1 (the durable failure record)", len(scans))
	}

	rec := scans[0]
	if rec.Success {
		t.Errorf("scan record Success = true, want false (Run returned an error)")
	}
	if rec.FailedStage != "connect" {
		t.Errorf("scan record FailedStage = %q, want %q", rec.FailedStage, "connect")
	}
	if !strings.Contains(rec.Error, "403") {
		t.Errorf("scan record Error = %q, want it to carry the underlying 403", rec.Error)
	}
	if rec.StartedAt.IsZero() || rec.FinishedAt.IsZero() {
		t.Errorf("scan record timestamps = %+v, want both StartedAt and FinishedAt populated", rec)
	}
	if rec.FinishedAt.Before(rec.StartedAt) {
		t.Errorf("scan record FinishedAt (%v) before StartedAt (%v)", rec.FinishedAt, rec.StartedAt)
	}
}

// TestPipeline_HealthyScan_RecordsSuccess is the companion positive case: a
// scan that completes without error must still commit a ScanRecord, now with
// Success=true and both failure fields empty — proving the fix didn't flip
// the healthy path's semantics while making the failure path durable.
func TestPipeline_HealthyScan_RecordsSuccess(t *testing.T) {
	be := &cannedbackend.CannedBackend{
		CannedResolutionFunc: func(callIndex int) string {
			t.Errorf("clean scan must make NO model call; got call %d", callIndex)
			return `{"action":"escalate"}`
		},
	}
	if err := be.Start(); err != nil {
		t.Fatalf("start cannedbackend: %v", err)
	}
	t.Cleanup(be.Stop)

	benign, _ := json.Marshal(map[string]string{"note": "routine heartbeat"})
	events := []event.Event{{
		ID: "evt-benign-scanrecord", Source: "aws", Type: "heartbeat", Actor: "ops-bot",
		Timestamp: time.Now().UTC(), Org: "atom", Payload: benign,
	}}

	st := newGitStore(t)
	cfg := pipeline.Config{
		Connector: connect.FromPath(writeEventsFile(t, events)),
		Client:    &inference.DirectClient{BaseURL: be.URL(), Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	sum, err := pipeline.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if sum.EventsScanned != 1 {
		t.Fatalf("EventsScanned = %d, want 1", sum.EventsScanned)
	}

	scans, lerr := st.LoadScans()
	if lerr != nil {
		t.Fatalf("LoadScans: %v", lerr)
	}
	if len(scans) != 1 {
		t.Fatalf("LoadScans returned %d records after a healthy scan, want exactly 1", len(scans))
	}

	rec := scans[0]
	if !rec.Success {
		t.Errorf("scan record Success = false, want true (Run returned no error)")
	}
	if rec.FailedStage != "" {
		t.Errorf("scan record FailedStage = %q, want empty on a successful scan", rec.FailedStage)
	}
	if rec.Error != "" {
		t.Errorf("scan record Error = %q, want empty on a successful scan", rec.Error)
	}
	if rec.EventsScanned != 1 {
		t.Errorf("scan record EventsScanned = %d, want 1", rec.EventsScanned)
	}
}
