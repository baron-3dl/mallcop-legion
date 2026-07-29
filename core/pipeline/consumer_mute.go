package pipeline

import (
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// muteNow is the clock the mute consumer reads to decide whether a mute
// directive's TTL (Meta.expires_at, mallcop feedback ... mute --ttl 30d) has
// elapsed. It is a package-level var — not a bare time.Now() call inline —
// so a deterministic-replay test can pin it to a fixed instant instead of
// racing the real wall clock at whatever moment CI happens to run. In
// production it is the unmodified real clock: "the scan's own clock" is
// simply whatever this returns at the single Apply() call each scan makes,
// which is consistent for every finding/directive compared during that run.
var muteNow = time.Now

// muteConsumer implements the 'mute' Op (Design §Gap C, mallcoppro-ae2):
// a mute directive DROPS findings matching Pattern while
// Directive.Meta.expires_at is still in the future, and STOPS dropping once
// that instant has passed — a time-boxed suppress, auto-expiring on the next
// replay rather than requiring an explicit unsuppress/unmute. 'mute' was
// already documented vocabulary (core/store/records.go's Directive doc,
// DirectiveMeta.ExpiresAt) with no wired consumer; this implements that
// verb, it does not add a new one.
//
// A mute with a zero ExpiresAt (Meta absent, or expires_at omitted/malformed
// — ParseMeta error) is treated as an indefinite mute (fail toward the
// operator's evident intent to silence the finding, same posture as
// suppress) rather than silently doing nothing.
func muteConsumer(v *FindingVerdict, d store.Directive, _ finding.Finding) {
	meta, err := d.ParseMeta()
	if err != nil || meta.ExpiresAt.IsZero() || muteNow().Before(meta.ExpiresAt) {
		v.Suppressed = true
		return
	}
	// Expired: the mute directive contributes nothing to this finding's
	// verdict. Leave v.Suppressed untouched — a mute never explicitly
	// "keeps" a finding, it only stops asserting "drop" once its TTL runs
	// out, exactly mirroring how an unregistered/no-op directive behaves.
}

// init wires the mute consumer onto the package's default dispatcher — the
// ONE Register call this file adds. defaultDirectiveDispatcher (declared in
// directives.go) is what applyDirectives/pipeline.go use, so this makes
// 'mute' honored by the scan pipeline without editing directives.go.
func init() {
	defaultDirectiveDispatcher.Register("mute", muteConsumer)
}
