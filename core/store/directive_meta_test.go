package store

import "testing"

// TestDirective_ParseMeta_Empty proves an absent Meta decodes to the zero
// DirectiveMeta and no error — directives issued before a given Meta field
// existed (or that never set one) must not be treated as malformed.
func TestDirective_ParseMeta_Empty(t *testing.T) {
	d := Directive{Op: "suppress"}
	m, err := d.ParseMeta()
	if err != nil {
		t.Fatalf("ParseMeta on nil Meta returned error: %v", err)
	}
	if m != (DirectiveMeta{}) {
		t.Fatalf("expected zero DirectiveMeta, got %+v", m)
	}
}

// TestDirective_ParseMeta_RoundTrip proves the documented Meta fields
// (expires_at/severity/weight/target_kind) survive a JSON round trip through
// Meta (json.RawMessage) without any store schema change.
func TestDirective_ParseMeta_RoundTrip(t *testing.T) {
	d := Directive{
		Op:      "mute",
		Pattern: "detector:secrets-exposure/secrets-exposure/*",
		Meta:    []byte(`{"expires_at":"2026-08-28T00:00:00Z","severity":"low","weight":0.5,"target_kind":"finding-key"}`),
	}
	m, err := d.ParseMeta()
	if err != nil {
		t.Fatalf("ParseMeta: %v", err)
	}
	if m.Severity != "low" || m.Weight != 0.5 || m.TargetKind != "finding-key" {
		t.Fatalf("ParseMeta wrong: %+v", m)
	}
	if m.ExpiresAt.IsZero() {
		t.Fatalf("expected non-zero ExpiresAt, got zero")
	}
}

// TestDirective_ParseMeta_InvalidJSON proves malformed Meta surfaces as an
// error rather than being silently swallowed into a zero value.
func TestDirective_ParseMeta_InvalidJSON(t *testing.T) {
	d := Directive{Op: "mute", Meta: []byte(`{not json`)}
	if _, err := d.ParseMeta(); err == nil {
		t.Fatal("expected error decoding invalid Meta JSON, got nil")
	}
}
