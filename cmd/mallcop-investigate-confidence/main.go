// Command mallcop-investigate-confidence is a pre_bead_close hook for the
// investigate disposition. It reads a JSON session summary from stdin, computes
// a structural confidence score, and exits 1 if confidence is below 0.55 —
// blocking the investigate close and triggering fan-out to the heal disposition.
//
// Input (JSON on stdin):
//
//	{
//	  "tool_calls":        N,   // total tool call count
//	  "distinct_tools":   N,   // number of different tools used
//	  "evidence_patterns": N,  // pre-counted evidence matches (optional; overrides reason_text scan)
//	  "iterations":        N,  // loop iteration count
//	  "reason_text":       "..." // reason text to scan for evidence patterns (if evidence_patterns omitted)
//	}
//
// Exit codes:
//
//	0 — confidence >= 0.55 (proceed with close)
//	1 — confidence < 0.55  (block close; trigger fan-out)
//	2 — bad input (malformed JSON, missing required fields)
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
)

// Scoring constants — ported from mallcop/src/mallcop/actors/confidence.py
const (
	toolCallWeight  = 0.04
	toolCallCap     = 8
	distinctWeight  = 0.08
	distinctCap     = 4
	evidenceWeight  = 0.04
	evidenceCap     = 5
	iterPenalty     = 0.02
	noiseFloor      = 0.05
	threshold       = 0.55
)

// evidencePatterns are the regex anchors that indicate concrete evidence
// citations in reason text. Ported from _EVIDENCE_PATTERNS in confidence.py.
var evidencePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}`),          // ISO date
	regexp.MustCompile(`\b\d{2}:\d{2}`),                  // time reference
	regexp.MustCompile(`(?i)\bbaseline\b`),
	regexp.MustCompile(`(?i)\bfrequency\b`),
	regexp.MustCompile(`(?i)\brelationship\b`),
	regexp.MustCompile(`(?i)\bactor:\w+`),                // actor:name reference
	regexp.MustCompile(`(?i)\bknown\b`),
	regexp.MustCompile(`(?i)\bpercentile\b`),
	regexp.MustCompile(`(?i)\bIP\s+\d+\.\d+`),           // IP address
	regexp.MustCompile(`(?i)\bfirst_seen\b|\blast_seen\b`),
	regexp.MustCompile(`(?i)\bcount\b`),
	regexp.MustCompile(`(?i)\bevents?\b`),
}

// Input is the JSON payload read from stdin.
type Input struct {
	ToolCalls        int     `json:"tool_calls"`
	DistinctTools    int     `json:"distinct_tools"`
	EvidencePatterns *int    `json:"evidence_patterns"` // optional; if nil, scan reason_text
	Iterations       int     `json:"iterations"`
	ReasonText       string  `json:"reason_text"`
}

// computeConfidence calculates a structural confidence score in [0.0, 1.0].
// A random noise floor of ±noiseFloor is added (non-deterministic by design).
func computeConfidence(in Input) float64 {
	// Tool call contribution
	tc := float64(min(in.ToolCalls, toolCallCap)) * toolCallWeight

	// Distinct tools contribution
	dt := float64(min(in.DistinctTools, distinctCap)) * distinctWeight

	// Evidence density
	var evidenceCount int
	if in.EvidencePatterns != nil {
		evidenceCount = *in.EvidencePatterns
	} else {
		for _, p := range evidencePatterns {
			if p.FindString(in.ReasonText) != "" {
				evidenceCount++
			}
		}
	}
	ev := float64(min(evidenceCount, evidenceCap)) * evidenceWeight

	// Iteration penalty: -0.02 per iteration above 3
	penalty := float64(max(0, in.Iterations-3)) * iterPenalty

	base := tc + dt + ev - penalty

	// Noise floor: ±0.05 uniform random (Kerckhoffs's principle)
	noise := (rand.Float64()*2 - 1) * noiseFloor

	score := base + noise
	return clamp(score, 0.0, 1.0)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	var in Input
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-investigate-confidence: bad input: %v\n", err)
		os.Exit(2)
	}

	score := computeConfidence(in)

	if score >= threshold {
		fmt.Fprintf(os.Stderr, "confidence %.3f >= %.2f — proceeding\n", score, threshold)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "confidence %.3f < %.2f — blocking close, triggering fan-out\n", score, threshold)
	os.Exit(1)
}
