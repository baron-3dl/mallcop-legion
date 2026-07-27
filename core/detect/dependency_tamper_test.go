package detect

import (
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// TestDependencyTamperReadsMetadataNestedShape is the regression guard for
// mallcoppro-9d6: dependency_tamper used to json.Unmarshal ev.Payload straight
// onto depPayload, which only populated fields for the FLAT production shape.
// Corpus/eval scenarios nest their discriminators under `metadata`, so every
// rule silently read empty strings and no finding fired — the identical
// data-drop config_drift carried before mallcoppro-192 fixed it.
//
// Each case wraps the SAME discriminators under `metadata` and asserts the rule
// still fires. The string-keyed fields go through metaStr; the bool (Direct) and
// the []string (added_packages) exercise metaBool / metaStrSlice.
func TestDependencyTamperReadsMetadataNestedShape(t *testing.T) {
	cases := []struct {
		name     string
		evType   string
		metadata map[string]any
	}{
		{
			name:   "hash-mismatch",
			evType: "package_install",
			metadata: map[string]any{
				"package":       "left-pad",
				"ecosystem":     "npm",
				"expected_hash": "aaaaaaaaaaaa",
				"actual_hash":   "bbbbbbbbbbbb",
			},
		},
		{
			name:   "suspicious-registry",
			evType: "package_install",
			metadata: map[string]any{
				"package":   "evil",
				"ecosystem": "npm",
				"registry":  "http://127.0.0.1:8080",
			},
		},
		{
			name:   "typosquat-added-package",
			evType: "lock_file_change",
			metadata: map[string]any{
				"ecosystem":      "npm",
				"added_packages": []any{"reqqests"},
			},
		},
		{
			name:   "unexpected-direct-dependency",
			evType: "dependency_add",
			metadata: map[string]any{
				"package":     "some-lib",
				"ecosystem":   "npm",
				"new_version": "1.0.0",
				"direct":      true,
			},
		},
		{
			name:   "version-downgrade",
			evType: "dependency_update",
			metadata: map[string]any{
				"package":     "openssl-wrapper",
				"ecosystem":   "npm",
				"old_version": "2.0.0",
				"new_version": "1.9.9",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := event.Event{
				ID: "dt-meta-" + c.name, Source: "npm", Type: c.evType,
				Actor: "ci", Timestamp: ts(16, 5),
				Payload: raw(t, map[string]any{
					"action":   c.evType,
					"metadata": c.metadata,
				}),
			}
			var fired bool
			for _, f := range Detect([]event.Event{ev}, &baseline.Baseline{}) {
				if f.Type == "dependency-tamper" {
					fired = true
				}
			}
			if !fired {
				t.Fatalf("dependency-tamper did NOT fire on metadata-nested %s event — the metadata-first read regressed", c.name)
			}
		})
	}
}

// TestDependencyTamperFlatShapeStillFires pins the production FLAT shape: the
// readDepPayload plumbing fix must not regress the pre-existing path where the
// discriminators sit at the payload root (mallcoppro-9d6).
func TestDependencyTamperFlatShapeStillFires(t *testing.T) {
	ev := event.Event{
		ID: "dt-flat", Source: "npm", Type: "package_install",
		Actor: "ci", Timestamp: ts(16, 6),
		Payload: raw(t, map[string]string{
			"package":       "left-pad",
			"ecosystem":     "npm",
			"expected_hash": "aaaaaaaaaaaa",
			"actual_hash":   "bbbbbbbbbbbb",
		}),
	}
	var fired bool
	for _, f := range Detect([]event.Event{ev}, &baseline.Baseline{}) {
		if f.Type == "dependency-tamper" {
			fired = true
		}
	}
	if !fired {
		t.Fatal("dependency-tamper did NOT fire on the flat production shape — the readDepPayload fix regressed the flat path")
	}
}
