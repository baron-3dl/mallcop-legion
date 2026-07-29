package pipeline

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// muteDirective builds a mute Directive whose Meta.expires_at is the given
// instant, mirroring what `mallcop feedback <id> mute --ttl 30d` persists.
func muteDirective(pattern string, expiresAt time.Time) store.Directive {
	meta, err := json.Marshal(map[string]string{"expires_at": expiresAt.UTC().Format(time.RFC3339)})
	if err != nil {
		panic(err)
	}
	return store.Directive{Op: "mute", Pattern: pattern, Meta: json.RawMessage(meta)}
}

// TestMuteConsumer_DropsBeforeExpiryKeepsAfter is the enforcement test for
// Gap C (mallcoppro-ae2): a mute directive drops the matching finding on a
// replay whose clock is still BEFORE Meta.expires_at, and the identical
// directive stream stops dropping it on a later replay whose clock is AFTER
// expires_at. Both replays go through applyDirectives (the pipeline's real
// entry point, defaultDirectiveDispatcher with 'mute' registered by this
// package's init()), not a hand-built dispatcher, so this proves the wiring
// pipeline.go actually uses.
//
// Determinism: the test pins muteNow (this package's clock var) to fixed
// instants for each replay instead of depending on real wall-clock time, so
// it is not a race against whatever moment CI happens to run — it is a
// deterministic replay of "the scan's own clock" at two chosen points.
func TestMuteConsumer_DropsBeforeExpiryKeepsAfter(t *testing.T) {
	orig := muteNow
	defer func() { muteNow = orig }()

	fixedNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := fixedNow.Add(30 * 24 * time.Hour) // 30d TTL from issuance

	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		muteDirective("detector:secrets-exposure/secrets-exposure/alice", expiresAt),
	}

	// Replay #1: scan clock is BEFORE expires_at — the mute is still active.
	muteNow = func() time.Time { return fixedNow.Add(1 * time.Hour) }
	kept := applyDirectives(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f2" {
		t.Fatalf("before expiry: expected only f2 kept, got %+v", kept)
	}

	// Replay #2: same directive stream, same findings — scan clock is now
	// AFTER expires_at. The mute must no longer drop f1.
	muteNow = func() time.Time { return expiresAt.Add(1 * time.Hour) }
	kept = applyDirectives(findings, directives)
	if len(kept) != 2 {
		t.Fatalf("after expiry: expected both findings kept, got %+v", kept)
	}
}

// TestMuteConsumer_NoExpiryNeverExpires proves a mute with no expires_at in
// Meta (Meta absent entirely) mutes indefinitely rather than silently doing
// nothing — the same fail-toward-operator-intent posture as suppress.
func TestMuteConsumer_NoExpiryNeverExpires(t *testing.T) {
	orig := muteNow
	defer func() { muteNow = orig }()
	muteNow = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }

	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	directives := []store.Directive{
		{Op: "mute", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	kept := applyDirectives(findings, directives)
	if len(kept) != 0 {
		t.Fatalf("expected mute with no expires_at to drop indefinitely, got %+v", kept)
	}
}
