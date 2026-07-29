package cli

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// seedFinding initializes a store at dir and appends one finding, returning the
// store path. It uses the CLI's own store-init lifecycle (openOrInitStore).
func seedFinding(t *testing.T, dir string, f finding.Finding) {
	t.Helper()
	st, err := openOrInitStore(dir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, err := st.Append(store.KindFindings, f); err != nil {
		t.Fatalf("append finding: %v", err)
	}
}

// TestFeedbackDismiss_WritesDirectiveReadableByLoadDirectives proves the CLI
// persists a suppress directive that LoadDirectives can read back — the bridge
// between the operator's decision and the next scan honoring it.
func TestFeedbackDismiss_WritesDirectiveReadableByLoadDirectives(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:        "finding-e1-secret-github-pat",
		Source:    "detector:secrets-exposure",
		Type:      "secrets-exposure",
		Actor:     "alice",
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Reason:    "github pat in payload",
	}
	seedFinding(t, dir, f)

	err := runFeedback([]string{f.ID, "dismiss", "--store", dir, "--reason", "known-good", "--by", "baron"})
	if err != nil {
		t.Fatalf("runFeedback dismiss: %v", err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "suppress" {
		t.Fatalf("Op = %q, want suppress", d.Op)
	}
	wantPattern := "detector:secrets-exposure/secrets-exposure/alice"
	if d.Pattern != wantPattern {
		t.Fatalf("Pattern = %q, want %q", d.Pattern, wantPattern)
	}
	if d.Actor != "baron" {
		t.Fatalf("Actor = %q, want baron", d.Actor)
	}
	if d.Reason != "known-good" {
		t.Fatalf("Reason = %q, want known-good", d.Reason)
	}
	// Meta records the verb distinctly for the audit trail.
	var meta map[string]string
	if err := json.Unmarshal(d.Meta, &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if meta["verb"] != "dismiss" {
		t.Fatalf("meta verb = %q, want dismiss", meta["verb"])
	}
}

// TestFeedbackApprove_RecordsVerbDistinctly proves approve also persists a
// suppress directive but tags the verb as approve.
func TestFeedbackApprove_RecordsVerbDistinctly(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:     "finding-e9-new-actor-bob",
		Source: "detector:new-actor",
		Type:   "new-actor",
		Actor:  "bob",
	}
	seedFinding(t, dir, f)

	if err := runFeedback([]string{f.ID, "approve", "--store", dir, "--by", "baron"}); err != nil {
		t.Fatalf("runFeedback approve: %v", err)
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 1 || directives[0].Op != "suppress" {
		t.Fatalf("approve did not persist a suppress directive: %+v", directives)
	}
	var meta map[string]string
	_ = json.Unmarshal(directives[0].Meta, &meta)
	if meta["verb"] != "approve" {
		t.Fatalf("meta verb = %q, want approve", meta["verb"])
	}
}

// TestFeedbackMute_WritesTimeBoxedDirective proves `mallcop feedback <id>
// mute --ttl 30d` persists a 'mute' Op (not 'suppress') whose
// Meta.expires_at core/store.Directive.ParseMeta decodes to ~30 days from
// issuance — the field core/pipeline's mute consumer reads (Gap C,
// mallcoppro-ae2).
func TestFeedbackMute_WritesTimeBoxedDirective(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:     "finding-mute-1",
		Source: "detector:secrets-exposure",
		Type:   "secrets-exposure",
		Actor:  "alice",
	}
	seedFinding(t, dir, f)

	before := time.Now().UTC()
	if err := runFeedback([]string{f.ID, "mute", "--ttl", "30d", "--store", dir, "--by", "baron"}); err != nil {
		t.Fatalf("runFeedback mute: %v", err)
	}
	after := time.Now().UTC()

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "mute" {
		t.Fatalf("Op = %q, want mute", d.Op)
	}
	meta, err := d.ParseMeta()
	if err != nil {
		t.Fatalf("ParseMeta: %v", err)
	}
	if meta.ExpiresAt.IsZero() {
		t.Fatal("expected ExpiresAt to be set for a mute directive")
	}
	// RFC3339 (what the CLI persists expires_at as, and what ParseMeta
	// decodes) truncates to whole seconds, so widen the window by 1s on
	// each side to tolerate that truncation rather than racing it.
	minExpiry := before.Add(30 * 24 * time.Hour).Add(-time.Second)
	maxExpiry := after.Add(30 * 24 * time.Hour).Add(time.Second)
	if meta.ExpiresAt.Before(minExpiry) || meta.ExpiresAt.After(maxExpiry) {
		t.Fatalf("ExpiresAt = %v, want between %v and %v", meta.ExpiresAt, minExpiry, maxExpiry)
	}
}

// TestFeedbackMute_RequiresTTL proves mute without --ttl fails cleanly and
// writes no directive, rather than silently muting forever.
func TestFeedbackMute_RequiresTTL(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{ID: "finding-mute-2", Source: "s", Type: "t", Actor: "a"}
	seedFinding(t, dir, f)

	err := runFeedback([]string{f.ID, "mute", "--store", dir})
	if err == nil {
		t.Fatal("expected error for mute with no --ttl, got nil")
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 0 {
		t.Fatalf("expected no directive written on --ttl error, got %d", len(directives))
	}
}

// TestFeedbackWatch_WritesFocusDirectiveWithExplicitWeight proves `mallcop
// feedback <id> watch --weight <n>` persists a 'focus' Op (the Op
// core/pipeline/consumer_attention.go's attentionWeightConsumer is registered
// on) whose Meta.weight round-trips through store.Directive.ParseMeta as the
// exact float64 the operator gave — the CLI issuance side of Gap C
// (mallcoppro-4da).
func TestFeedbackWatch_WritesFocusDirectiveWithExplicitWeight(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:     "finding-watch-1",
		Source: "detector:secrets-exposure",
		Type:   "secrets-exposure",
		Actor:  "alice",
	}
	seedFinding(t, dir, f)

	if err := runFeedback([]string{f.ID, "watch", "--weight", "2.5", "--store", dir, "--by", "baron"}); err != nil {
		t.Fatalf("runFeedback watch: %v", err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "focus" {
		t.Fatalf("Op = %q, want focus", d.Op)
	}
	wantPattern := "detector:secrets-exposure/secrets-exposure/alice"
	if d.Pattern != wantPattern {
		t.Fatalf("Pattern = %q, want %q", d.Pattern, wantPattern)
	}
	if d.Actor != "baron" {
		t.Fatalf("Actor = %q, want baron", d.Actor)
	}
	meta, err := d.ParseMeta()
	if err != nil {
		t.Fatalf("ParseMeta: %v", err)
	}
	if meta.Weight != 2.5 {
		t.Fatalf("meta.Weight = %v, want 2.5", meta.Weight)
	}
	if meta.Severity != "" {
		t.Fatalf("watch must never set Severity, got %q", meta.Severity)
	}
}

// TestFeedbackWatch_OmitsWeightMetaWhenFlagAbsent proves a bare `watch` (no
// --weight) writes a focus directive with NO Meta.weight key at all, so
// core/pipeline's attentionWeightConsumer falls through to its own
// defaultFocusWeight rather than the CLI silently encoding a second copy of
// that default.
func TestFeedbackWatch_OmitsWeightMetaWhenFlagAbsent(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{ID: "finding-watch-2", Source: "s", Type: "t", Actor: "a"}
	seedFinding(t, dir, f)

	if err := runFeedback([]string{f.ID, "watch", "--store", dir}); err != nil {
		t.Fatalf("runFeedback watch: %v", err)
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	var raw map[string]any
	if err := json.Unmarshal(directives[0].Meta, &raw); err != nil {
		t.Fatalf("decode raw meta: %v", err)
	}
	if _, ok := raw["weight"]; ok {
		t.Fatalf("expected no weight key in Meta when --weight omitted, got %v", raw)
	}
}

// TestFeedbackSeverity_WritesSeverityDirective proves `mallcop feedback <id>
// severity <level>` persists a 'severity' Op (the Op
// core/pipeline/consumer_attention.go's severityOverrideConsumer is registered
// on) whose Meta.severity round-trips through ParseMeta as the given level —
// the CLI issuance side of Gap C (mallcoppro-4da).
func TestFeedbackSeverity_WritesSeverityDirective(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{
		ID:     "finding-sev-1",
		Source: "detector:new-actor",
		Type:   "new-actor",
		Actor:  "bob",
	}
	seedFinding(t, dir, f)

	if err := runFeedback([]string{f.ID, "severity", "critical", "--store", dir, "--by", "baron"}); err != nil {
		t.Fatalf("runFeedback severity: %v", err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "severity" {
		t.Fatalf("Op = %q, want severity", d.Op)
	}
	wantPattern := "detector:new-actor/new-actor/bob"
	if d.Pattern != wantPattern {
		t.Fatalf("Pattern = %q, want %q", d.Pattern, wantPattern)
	}
	meta, err := d.ParseMeta()
	if err != nil {
		t.Fatalf("ParseMeta: %v", err)
	}
	if meta.Severity != "critical" {
		t.Fatalf("meta.Severity = %q, want critical", meta.Severity)
	}
	if meta.Weight != 0 {
		t.Fatalf("severity must never set Weight, got %v", meta.Weight)
	}
}

// TestFeedbackSeverity_RequiresLevel proves severity with no level argument
// fails cleanly and writes no directive, rather than persisting an empty
// override.
func TestFeedbackSeverity_RequiresLevel(t *testing.T) {
	dir := t.TempDir()
	f := finding.Finding{ID: "finding-sev-2", Source: "s", Type: "t", Actor: "a"}
	seedFinding(t, dir, f)

	err := runFeedback([]string{f.ID, "severity", "--store", dir})
	if err == nil {
		t.Fatal("expected error for severity with no level, got nil")
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 0 {
		t.Fatalf("expected no directive written when severity level is missing, got %d", len(directives))
	}
}

// TestFeedback_BadFindingIDErrorsCleanly proves an unknown finding-id fails with
// a clear error and writes NO directive.
func TestFeedback_BadFindingIDErrorsCleanly(t *testing.T) {
	dir := t.TempDir()
	seedFinding(t, dir, finding.Finding{ID: "finding-real", Source: "s", Type: "t", Actor: "a"})

	err := runFeedback([]string{"finding-does-not-exist", "dismiss", "--store", dir})
	if err == nil {
		t.Fatal("expected error for unknown finding-id, got nil")
	}

	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 0 {
		t.Fatalf("no directive should be written on a bad finding-id, got %d", len(directives))
	}
}

func TestFeedback_BadVerbErrors(t *testing.T) {
	dir := t.TempDir()
	seedFinding(t, dir, finding.Finding{ID: "finding-real", Source: "s", Type: "t", Actor: "a"})
	if err := runFeedback([]string{"finding-real", "frobnicate", "--store", dir}); err == nil {
		t.Fatal("expected error for unknown verb")
	}
}

func TestFeedback_MissingStoreErrors(t *testing.T) {
	if err := runFeedback([]string{"finding-real", "dismiss"}); err == nil {
		t.Fatal("expected error when --store is missing")
	}
}

// TestFeedbackReportMiss_WritesStructuredDirective proves `mallcop feedback
// report-miss` persists a report-miss directive whose STRUCTURED meta carries the
// (source, event_type, actor, window), whose Reason holds the free-text
// description (audit only), and which collect surfaces as a recall gap — the
// operator false-NEGATIVE seam distinct from approve|dismiss suppression.
func TestFeedbackReportMiss_WritesStructuredDirective(t *testing.T) {
	dir := t.TempDir()
	// report-miss needs no finding — initialize the store directly.
	if _, err := openOrInitStore(dir); err != nil {
		t.Fatalf("init store: %v", err)
	}

	err := runFeedback([]string{"report-miss",
		"--store", dir,
		"--source", "github",
		"--event-type", "github.permission.grant",
		"--actor", "mallory",
		"--window", "off-hours",
		"--description", "mallory grants herself owner off-hours",
		"--by", "baron",
	})
	if err != nil {
		t.Fatalf("runFeedback report-miss: %v", err)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	directives, err := st.LoadDirectives()
	if err != nil {
		t.Fatalf("load directives: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}
	d := directives[0]
	if d.Op != "report-miss" {
		t.Fatalf("Op = %q, want report-miss", d.Op)
	}
	if d.Actor != "baron" {
		t.Fatalf("Actor = %q, want baron", d.Actor)
	}
	if d.Reason != "mallory grants herself owner off-hours" {
		t.Fatalf("Reason (audit description) = %q", d.Reason)
	}
	var meta struct {
		Source    string `json:"source"`
		EventType string `json:"event_type"`
		Actor     string `json:"actor"`
		Window    string `json:"window"`
	}
	if err := json.Unmarshal(d.Meta, &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if meta.Source != "github" || meta.EventType != "github.permission.grant" ||
		meta.Actor != "mallory" || meta.Window != "off-hours" {
		t.Fatalf("meta = %+v, want structured github/permission.grant/mallory/off-hours", meta)
	}
}

// TestFeedbackReportMiss_RequiresStructuredTarget proves a bare report-miss (only
// a --description, no --source/--event-type) is rejected and writes NO directive:
// the description never crosses into a proposal, so a description-only report would
// be a silent no-op gap.
func TestFeedbackReportMiss_RequiresStructuredTarget(t *testing.T) {
	dir := t.TempDir()
	if _, err := openOrInitStore(dir); err != nil {
		t.Fatalf("init store: %v", err)
	}
	err := runFeedback([]string{"report-miss", "--store", dir, "--description", "we missed something"})
	if err == nil {
		t.Fatal("expected error for a report-miss with no --source/--event-type")
	}
	st, _ := store.Open(dir)
	directives, _ := st.LoadDirectives()
	if len(directives) != 0 {
		t.Fatalf("no directive should be written for a bare report-miss, got %d", len(directives))
	}
}

func TestFeedbackReportMiss_MissingStoreErrors(t *testing.T) {
	if err := runFeedback([]string{"report-miss", "--source", "github", "--event-type", "x"}); err == nil {
		t.Fatal("expected error when --store is missing")
	}
}
