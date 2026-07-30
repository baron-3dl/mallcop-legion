package connect

import (
	"context"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// MultiConnector fans one scan cycle out over several sub-connectors and
// concatenates their events into a single batch. It is the seam that lets a
// config-driven `mallcop scan` pull from every configured source (file, github,
// cloud, …) in ONE pass without the pipeline knowing more than one
// Connector exists.
//
// It carries NO source-specific logic — it only composes Connectors — so it
// stays inside the core/connect purity budget (stdlib + pkg/event; the
// core/lint import-lint stays green).
//
// Ordering: because the detector floor is whole-corpus (see connect.go), a scan
// depends on the SET of events, not their order across sources. MultiConnector
// therefore preserves each sub-connector's internal order and concatenates the
// batches in sub-connector declaration order — a deterministic, sufficient
// contract, with no streaming/interleaving guarantee.
//
// Fail-loud: if ANY sub-connector's Pull returns an error, MultiConnector's Pull
// returns that error and no events. A configured source that fails must HALT the
// scan — never silently under-report, which would tell the operator a source was
// scanned when it was not (the same posture as FileConnector's malformed-line
// error).
type MultiConnector struct {
	subs []Connector
}

// Multi returns a Connector that pulls from every sub-connector and concatenates
// the results. With zero sub-connectors it yields a clean scan over zero events
// (a valid, empty batch — mirroring an empty file source).
func Multi(subs ...Connector) *MultiConnector {
	return &MultiConnector{subs: subs}
}

// compile-time proof MultiConnector satisfies the seam.
var _ Connector = (*MultiConnector)(nil)

// Diagnosables returns every sub-connector that implements Diagnosable, in
// declaration order (mallcoppro-d3f veracity rework, Route 1). MultiConnector
// itself deliberately does NOT implement Diagnosable — it is a pure
// composition with no diagnosis of its own to offer — so a caller asserting
// directly on the composed Connector (as cli/scan.go's buildConnectors ALWAYS
// returns: connect.Multi(subs...), even for a single configured source) finds
// nothing. This method is the escape hatch: it reaches into the actual leaf
// connectors — the kind:cloud ExecConnector, the one production Diagnosable —
// so a Pull failure's self-diagnosis is never silently dropped just because
// the top-level Connector is a MultiConnector.
func (m *MultiConnector) Diagnosables() []Diagnosable {
	var out []Diagnosable
	for _, sub := range m.subs {
		if d, ok := sub.(Diagnosable); ok {
			out = append(out, d)
		}
	}
	return out
}

// Pull calls each sub-connector's Pull in declaration order and concatenates the
// returned batches. It honors ctx: cancellation/deadline is checked before each
// sub-connector, and ctx is threaded into every sub-connector's Pull so a
// source doing I/O aborts promptly. The first sub-connector error halts the
// scan and is returned as-is (no partial batch).
func (m *MultiConnector) Pull(ctx context.Context) ([]event.Event, error) {
	var events []event.Event
	for _, sub := range m.subs {
		// Honor cancellation between sources so a cancelled scan stops before
		// starting the next (possibly expensive) sub-connector.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := sub.Pull(ctx)
		if err != nil {
			// Fail loud: a configured source that errors halts the whole scan.
			return nil, err
		}
		events = append(events, batch...)
	}
	return events, nil
}
