package router

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"gopkg.in/yaml.v3"
)

// Overlay filenames written into the customer store overlay dir. They mirror the
// mallcop connect/detect data lanes (learned_mappings.yaml source→action→type;
// tuning.yaml detector→extra_*→[values]) so `mallcop scan --tuning <dir>/tuning.yaml`
// and the learned-mapping overlay pick them up unchanged.
const (
	learnedMappingsFile = "learned_mappings.yaml"
	tuningFile          = "tuning.yaml"
	suppressionsFile    = "suppressions.yaml"
)

// WriteOverlay applies one add-only proposal to the customer store overlay in
// dir, APPEND-ONLY, and returns the file it touched. It mirrors the self-ext
// guard's widen-only contract (checkMappingWidenOnly, guard.go:295): an existing
// (source, action) mapping is FROZEN — re-mapping it to the same target is an
// idempotent no-op, but RETARGETING it to a different type is refused; only NEW
// keys are appended. Tuning values are merged additively (dedup, never removed).
//
// It is exported so the operator pipeline can also use it to apply the proposal
// to a throwaway worktree before gating (the same append-only write, a different
// dir). knownTypes is the closed vocabulary a mapping target is re-validated
// against (belt-and-suspenders behind the proposer's strict parse).
func WriteOverlay(dir string, p proposer.Proposal, knownTypes map[string]bool) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("router: overlay dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("router: create overlay dir: %w", err)
	}
	switch p.Kind {
	case proposer.KindMapping:
		return writeMappingOverlay(dir, p.Mapping, knownTypes)
	case proposer.KindTuning:
		return writeTuningOverlay(dir, p.Tuning)
	case proposer.KindOwnerSuppress:
		return writeSuppressionOverlay(dir, p.Owner)
	default:
		return "", fmt.Errorf("router: WriteOverlay: unroutable proposal kind %q", p.Kind)
	}
}

// writeMappingOverlay appends source→raw_action→event_type to learned_mappings.yaml,
// refusing to retarget an existing (source, action).
func writeMappingOverlay(dir string, m *proposer.MappingProposal, knownTypes map[string]bool) (string, error) {
	if m == nil {
		return "", fmt.Errorf("router: mapping proposal has nil payload")
	}
	source := strings.TrimSpace(m.Source)
	action := strings.TrimSpace(m.RawAction)
	target := strings.ToLower(strings.TrimSpace(m.EventType))
	if source == "" || action == "" || target == "" {
		return "", fmt.Errorf("router: mapping proposal missing source/raw_action/event_type")
	}
	// Re-validate the target against the closed vocabulary (fail-loud, like
	// overlay.ParseLearnedMappings) when one was supplied.
	if len(knownTypes) > 0 && !knownTypes[target] {
		return "", fmt.Errorf("router: mapping target %q is not in the closed vocabulary (refusing to write a net-new type)", m.EventType)
	}

	path := filepath.Join(dir, learnedMappingsFile)
	var doc map[string]map[string]string
	if err := readYAML(path, &doc); err != nil {
		return "", err
	}
	if doc == nil {
		doc = map[string]map[string]string{}
	}
	if doc[source] == nil {
		doc[source] = map[string]string{}
	}
	if existing, ok := doc[source][action]; ok {
		if existing == target {
			return path, nil // idempotent no-op
		}
		return "", fmt.Errorf("router: refusing to retarget frozen mapping %s/%s from %q to %q (widen-only: existing keys are immutable)",
			source, action, existing, target)
	}
	doc[source][action] = target
	if err := writeYAML(path, doc, mappingHeader); err != nil {
		return "", err
	}
	return path, nil
}

// writeTuningOverlay merges added values into detector→extra_*→[values] in
// tuning.yaml, additively (dedup preserved, nothing ever removed).
//
// The overlay key is NORMALIZED via detect.TuningKey (mallcoppro-b42): a
// TuningDelta.Detector arrives in the detector-REGISTRY convention (kebab-case,
// e.g. "priv-escalation" — what core/collect.DetectorGaps and
// detect.Detector.Name() both use), but detectors/tuning.yaml's section keys
// are Go-struct-field snake_case (core/detect/tuning.go's yaml tags, e.g.
// "priv_escalation"). Writing the RAW (unnormalized) family as the map key
// produces a tuning.yaml that LoadTuningFile's strict KnownFields decode
// rejects outright as an unknown section — a real widen would silently never
// load. detect.TuningKey is the ONE place both the write side (here) and the
// read side (core/detect/tuning.go) agree on, so a real "priv-escalation" gap
// widen lands under "priv_escalation" — the key the detector actually reads.
func writeTuningOverlay(dir string, td *proposer.TuningDelta) (string, error) {
	if td == nil {
		return "", fmt.Errorf("router: tuning proposal has nil payload")
	}
	detector := detect.TuningKey(td.Detector)
	key := strings.ToLower(strings.TrimSpace(td.Key))
	if detector == "" || key == "" || len(td.AddedValues) == 0 {
		return "", fmt.Errorf("router: tuning proposal missing detector/key/added_values")
	}
	if !proposer.IsAdditiveTuningKey(key) {
		return "", fmt.Errorf("router: refusing to write non-additive tuning key %q", td.Key)
	}
	// SCHEMA GATE (mallcoppro-2c2, defense in depth): even a key that passes
	// IsAdditiveTuningKey says nothing about whether THIS detector's family has
	// a loadable tuning.yaml section, or whether the key belongs to THAT
	// section's schema — core/detect/tuning.go's strict KnownFields decode
	// rejects both an unknown top-level section and a key absent from a known
	// section's struct. Router.Route's humanGateReason already screens this
	// on the primary path; this is the belt to that suspenders for ANY caller
	// of the exported WriteOverlay/writeTuningOverlay (e.g. cli/selfext.go's
	// proposeGateViaWorktree, which writes ahead of Route's own gate) — this
	// function must never produce a document the real loader then rejects.
	if !detect.KnownTuningSection(detector) {
		return "", fmt.Errorf("router: refusing to write tuning section %q (detector %q has no loadable tuning.yaml section — core/detect.LoadTuningFile would hard-reject it on the next scan)", detector, td.Detector)
	}
	if !detect.KnownTuningKey(detector, key) {
		return "", fmt.Errorf("router: refusing to write tuning key %q under section %q (not part of its loadable schema — core/detect.LoadTuningFile would hard-reject it on the next scan)", key, detector)
	}

	path := filepath.Join(dir, tuningFile)
	var doc map[string]map[string][]string
	if err := readYAML(path, &doc); err != nil {
		return "", err
	}
	if doc == nil {
		doc = map[string]map[string][]string{}
	}
	if doc[detector] == nil {
		doc[detector] = map[string][]string{}
	}
	seen := map[string]bool{}
	merged := make([]string, 0, len(doc[detector][key])+len(td.AddedValues))
	for _, v := range doc[detector][key] {
		cv := strings.ToLower(strings.TrimSpace(v))
		if cv == "" || seen[cv] {
			continue
		}
		seen[cv] = true
		merged = append(merged, cv)
	}
	for _, v := range td.AddedValues {
		cv := strings.ToLower(strings.TrimSpace(v))
		if cv == "" || seen[cv] {
			continue
		}
		seen[cv] = true
		merged = append(merged, cv)
	}
	sort.Strings(merged)
	doc[detector][key] = merged
	if err := writeYAML(path, doc, tuningHeader); err != nil {
		return "", err
	}
	return path, nil
}

// suppressionEntry is one tenant-scoped owner suppression on disk.
type suppressionEntry struct {
	FindingType string `yaml:"finding_type"`
	Scope       string `yaml:"scope"`
}

// suppressionDoc is the append-only suppressions.yaml shape.
type suppressionDoc struct {
	Suppressions []suppressionEntry `yaml:"suppressions"`
}

// writeSuppressionOverlay appends a tenant-scoped owner suppression to
// suppressions.yaml, idempotently (a duplicate (finding_type, scope) is a no-op).
func writeSuppressionOverlay(dir string, s *proposer.OwnerSuppression) (string, error) {
	if s == nil {
		return "", fmt.Errorf("router: owner suppression has nil payload")
	}
	ft := strings.TrimSpace(s.FindingType)
	scope := strings.TrimSpace(s.Scope)
	if ft == "" || scope == "" {
		return "", fmt.Errorf("router: owner suppression missing finding_type/scope")
	}
	if isGlobalScope(scope) {
		return "", fmt.Errorf("router: refusing to write a global suppression as a tenant overlay")
	}

	path := filepath.Join(dir, suppressionsFile)
	var doc suppressionDoc
	if err := readYAML(path, &doc); err != nil {
		return "", err
	}
	for _, e := range doc.Suppressions {
		if e.FindingType == ft && e.Scope == scope {
			return path, nil // idempotent no-op
		}
	}
	doc.Suppressions = append(doc.Suppressions, suppressionEntry{FindingType: ft, Scope: scope})
	if err := writeYAML(path, doc, suppressionHeader); err != nil {
		return "", err
	}
	return path, nil
}

const mappingHeader = "# learned_mappings.yaml — tenant overlay (widen-only DATA), append-only.\n" +
	"# Shape: source -> { rawAction: event_type }. Written by the K8 autonomy router.\n"

const tuningHeader = "# tuning.yaml — tenant overlay (widen-only DATA), additive-only.\n" +
	"# Shape: detector -> { extra_*: [values] }. Written by the K8 autonomy router.\n"

const suppressionHeader = "# suppressions.yaml — tenant-scoped owner suppressions (c8e). Never auto-contributed to OSS.\n"

// readYAML decodes path into v; a missing file leaves v at its zero value (not an
// error — the overlay starts empty). A malformed file is a fail-loud error.
func readYAML(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("router: read overlay %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("router: parse overlay %q: %w", path, err)
	}
	return nil
}

// writeYAML marshals v with a leading header comment and writes it to path.
func writeYAML(path string, v any, header string) error {
	body, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("router: marshal overlay %q: %w", path, err)
	}
	out := append([]byte(header), body...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("router: write overlay %q: %w", path, err)
	}
	return nil
}
