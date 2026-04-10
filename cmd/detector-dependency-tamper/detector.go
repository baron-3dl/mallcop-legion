package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// depTamperEventTypes are event types that carry dependency change signals.
var depTamperEventTypes = map[string]bool{
	"dependency_update":  true,
	"dependency_add":     true,
	"dependency_remove":  true,
	"lock_file_change":   true,
	"package_install":    true,
	"dependency_change":  true,
}

// typosquatPatterns detect common typosquatting patterns relative to known packages.
var typosquatPatterns = []*regexp.Regexp{
	// Repeated chars in common sequences: reqqests, requestss, lodaash.
	regexp.MustCompile(`qq|ss{2,}|aa{2,}|oo{2,}|ll{2,}|tt{2,}`),
	// Known popular package names with common char substitutions or additions.
	regexp.MustCompile(`(?i)^(requ[e3]sts?|req-uests?|r-equests?)$`),
	regexp.MustCompile(`(?i)^(lod[a4]sh|lodash-|l0dash)$`),
	regexp.MustCompile(`(?i)^(expresss|exp-ress)$`),
	regexp.MustCompile(`(?i)^(cross-fetch-?polyfill)$`),
}

// suspiciousRegistries are non-standard package registry hosts.
var suspiciousRegistries = []string{
	"http://",      // non-TLS registry
	"localhost",
	"127.0.0.1",
	"192.168.",
	"10.",
	"172.16.",
	"172.17.",
	"172.18.",
}

// depPayload is the expected payload for dependency change events.
type depPayload struct {
	// Package being changed.
	Package  string `json:"package"`
	Ecosystem string `json:"ecosystem"` // "npm", "pypi", "go", "maven", etc.

	// Version change.
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`

	// Hash/integrity fields.
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`

	// Registry source.
	Registry string `json:"registry"`

	// For lock file changes: list of added packages.
	AddedPackages   []string `json:"added_packages"`
	RemovedPackages []string `json:"removed_packages"`

	// Direct vs transitive.
	Direct bool `json:"direct"`
}

// evaluate returns findings for dependency supply chain anomalies.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	if !depTamperEventTypes[ev.Type] {
		return nil
	}

	if len(ev.Payload) == 0 {
		return nil
	}

	var dp depPayload
	_ = json.Unmarshal(ev.Payload, &dp)

	var findings []finding.Finding

	// Rule 1: Hash mismatch — highest severity (definitive tampering signal).
	if dp.ExpectedHash != "" && dp.ActualHash != "" && dp.ExpectedHash != dp.ActualHash {
		evidence, _ := json.Marshal(map[string]string{
			"actor":         ev.Actor,
			"package":       dp.Package,
			"ecosystem":     dp.Ecosystem,
			"expected_hash": dp.ExpectedHash,
			"actual_hash":   dp.ActualHash,
			"rule":          "hash-mismatch",
		})
		findings = append(findings, finding.Finding{
			ID:        "finding-" + ev.ID + "-hash",
			Source:    "detector:dependency-tamper",
			Severity:  "critical",
			Type:      "dependency-tamper",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("dependency hash mismatch for %q (%s): expected %s got %s", dp.Package, dp.Ecosystem, dp.ExpectedHash[:min(8, len(dp.ExpectedHash))], dp.ActualHash[:min(8, len(dp.ActualHash))]),
			Evidence:  evidence,
		})
	}

	// Rule 2: Suspicious registry source.
	if dp.Registry != "" {
		for _, suspicious := range suspiciousRegistries {
			if strings.Contains(strings.ToLower(dp.Registry), suspicious) {
				evidence, _ := json.Marshal(map[string]string{
					"actor":     ev.Actor,
					"package":   dp.Package,
					"registry":  dp.Registry,
					"ecosystem": dp.Ecosystem,
					"rule":      "suspicious-registry",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-registry",
					Source:    "detector:dependency-tamper",
					Severity:  "critical",
					Type:      "dependency-tamper",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    fmt.Sprintf("package %q (%s) installed from suspicious registry: %s", dp.Package, dp.Ecosystem, dp.Registry),
					Evidence:  evidence,
				})
				break
			}
		}
	}

	// Rule 3: Unexpected transitive additions (lock file change adds unlisted packages).
	for _, added := range dp.AddedPackages {
		// Check for typosquatting patterns.
		if isTyposquat(added) {
			evidence, _ := json.Marshal(map[string]string{
				"actor":     ev.Actor,
				"package":   added,
				"ecosystem": dp.Ecosystem,
				"rule":      "typosquatting",
			})
			findings = append(findings, finding.Finding{
				ID:        "finding-" + ev.ID + "-typosquat-" + sanitizeID(added),
				Source:    "detector:dependency-tamper",
				Severity:  "high",
				Type:      "dependency-tamper",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("potential typosquatting package added: %q", added),
				Evidence:  evidence,
			})
		}
	}

	// Rule 4: Direct dependency unexpectedly added (not a lock-file transitive).
	if ev.Type == "dependency_add" && dp.Package != "" && dp.Direct {
		// Flag direct additions at medium severity for review.
		evidence, _ := json.Marshal(map[string]string{
			"actor":      ev.Actor,
			"package":    dp.Package,
			"version":    dp.NewVersion,
			"ecosystem":  dp.Ecosystem,
			"registry":   dp.Registry,
			"rule":       "unexpected-direct-dependency",
		})
		findings = append(findings, finding.Finding{
			ID:        "finding-" + ev.ID + "-add",
			Source:    "detector:dependency-tamper",
			Severity:  "medium",
			Type:      "dependency-tamper",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("new direct dependency added by %q: %s@%s (%s)", ev.Actor, dp.Package, dp.NewVersion, dp.Ecosystem),
			Evidence:  evidence,
		})
	}

	// Rule 5: Downgrade — version goes backwards (possible rollback to vulnerable version).
	if dp.OldVersion != "" && dp.NewVersion != "" {
		if isDowngrade(dp.OldVersion, dp.NewVersion) {
			evidence, _ := json.Marshal(map[string]string{
				"actor":       ev.Actor,
				"package":     dp.Package,
				"old_version": dp.OldVersion,
				"new_version": dp.NewVersion,
				"ecosystem":   dp.Ecosystem,
				"rule":        "version-downgrade",
			})
			findings = append(findings, finding.Finding{
				ID:        "finding-" + ev.ID + "-downgrade",
				Source:    "detector:dependency-tamper",
				Severity:  "high",
				Type:      "dependency-tamper",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    fmt.Sprintf("dependency %q (%s) downgraded by %q: %s → %s", dp.Package, dp.Ecosystem, ev.Actor, dp.OldVersion, dp.NewVersion),
				Evidence:  evidence,
			})
		}
	}

	return findings
}

// isTyposquat returns true when the package name matches a known typosquatting
// pattern.
func isTyposquat(name string) bool {
	for _, re := range typosquatPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// isDowngrade returns a heuristic true when newVersion looks lower than oldVersion.
// Uses a simple string comparison after stripping "v" prefix — not semver-exact.
func isDowngrade(oldVer, newVer string) bool {
	old := strings.TrimPrefix(oldVer, "v")
	nw := strings.TrimPrefix(newVer, "v")
	// Compare lexicographically: "2.0.0" > "1.9.9" works for simple cases.
	return nw < old
}

// sanitizeID returns a string safe to use in finding IDs.
func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "@", "-")
	s = strings.ReplaceAll(s, " ", "-")
	re := regexp.MustCompile(`[^a-zA-Z0-9\-_]`)
	return re.ReplaceAllString(s, "")
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
