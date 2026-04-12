package main

import (
	"math"
	"testing"
)

// ptr is a helper to get a pointer to an int literal.
func ptr(n int) *int { return &n }

// TestZeroToolDegenerate: no tool calls, no distinct tools, no evidence, no
// iterations. Score must be in the noise-floor range [0, noiseFloor] because
// the deterministic base is 0.0 and noise is at most +noiseFloor.
func TestZeroToolDegenerate(t *testing.T) {
	in := Input{
		ToolCalls:     0,
		DistinctTools: 0,
		Iterations:    0,
		ReasonText:    "",
	}
	for i := 0; i < 200; i++ {
		score := computeConfidence(in)
		if score < 0.0 || score > noiseFloor+1e-9 {
			t.Fatalf("zero-tool degenerate: score %.4f out of expected [0, %.2f]", score, noiseFloor)
		}
	}
}

// TestMaxInputsAlwaysAboveThreshold: fully saturated inputs (8 tool calls, 4
// distinct, 5 evidence, 0 extra iterations) produce a deterministic base of
// 0.32 + 0.32 + 0.20 = 0.84. With noise ≤ +0.05 the floor is 0.79 — well
// above the 0.55 threshold in all trials.
func TestMaxInputsAlwaysAboveThreshold(t *testing.T) {
	in := Input{
		ToolCalls:        8,
		DistinctTools:    4,
		EvidencePatterns: ptr(5),
		Iterations:       0,
	}
	for i := 0; i < 200; i++ {
		score := computeConfidence(in)
		if score < threshold {
			t.Fatalf("max-inputs trial %d: score %.4f unexpectedly below threshold %.2f", i, score, threshold)
		}
	}
}

// TestThresholdBoundaryJustBelow: construct an input whose deterministic base
// sits so far below 0.55 that even +noiseFloor cannot raise it above threshold.
// base = 2*0.04 + 1*0.08 + 0*0.04 - 0 = 0.16; 0.16 + 0.05 = 0.21 < 0.55.
func TestThresholdBoundaryAlwaysBelow(t *testing.T) {
	in := Input{
		ToolCalls:        2,
		DistinctTools:    1,
		EvidencePatterns: ptr(0),
		Iterations:       0,
	}
	for i := 0; i < 200; i++ {
		score := computeConfidence(in)
		if score >= threshold {
			t.Fatalf("below-threshold trial %d: score %.4f unexpectedly at/above threshold %.2f", i, score, threshold)
		}
	}
}

// TestIterationPenalty: adding extra iterations reduces the score. With 10
// iterations the penalty is (10-3)*0.02 = 0.14. Compare a baseline with 3
// iterations (no penalty) — the 10-iteration variant should consistently score
// lower when using a fixed evidence pre-count and no noise by using many trials
// and checking the average difference is close to the expected penalty.
func TestIterationPenalty(t *testing.T) {
	base := Input{
		ToolCalls:        6,
		DistinctTools:    3,
		EvidencePatterns: ptr(3),
		Iterations:       3, // no penalty
	}
	penalized := Input{
		ToolCalls:        6,
		DistinctTools:    3,
		EvidencePatterns: ptr(3),
		Iterations:       10, // penalty = 7 * 0.02 = 0.14
	}

	const n = 1000
	var sumBase, sumPenalized float64
	for i := 0; i < n; i++ {
		sumBase += computeConfidence(base)
		sumPenalized += computeConfidence(penalized)
	}
	avgBase := sumBase / n
	avgPenalized := sumPenalized / n
	expectedPenalty := float64(10-3) * iterPenalty // 0.14

	got := avgBase - avgPenalized
	if math.Abs(got-expectedPenalty) > 0.02 { // allow 0.02 tolerance
		t.Fatalf("iteration penalty: expected ~%.3f difference, got %.3f (base=%.3f penalized=%.3f)",
			expectedPenalty, got, avgBase, avgPenalized)
	}
}

// TestNoiseFloorBounds: over many trials the score must always be clamped to
// [0.0, 1.0] and the noise contribution must not exceed ±noiseFloor.
// We test this with a mid-range input and assert all values are in [0,1].
func TestNoiseFloorBounds(t *testing.T) {
	in := Input{
		ToolCalls:        4,
		DistinctTools:    2,
		EvidencePatterns: ptr(2),
		Iterations:       3,
	}
	for i := 0; i < 500; i++ {
		score := computeConfidence(in)
		if score < 0.0 || score > 1.0 {
			t.Fatalf("noise floor bounds: score %.6f out of [0,1] on trial %d", score, i)
		}
	}
}

// TestEvidencePatternScan: reason_text containing multiple evidence anchors is
// counted correctly. We inject text that matches exactly 4 of the 12 patterns
// (ISO date, time, baseline, count) and check the evidence contribution lands
// near 4*0.04 = 0.16.
func TestEvidencePatternScan(t *testing.T) {
	in := Input{
		ToolCalls:     0,
		DistinctTools: 0,
		Iterations:    0,
		ReasonText:    "On 2024-03-15 at 14:30 we observed a baseline anomaly with a high count.",
	}
	// Patterns matched: ISO date (\d{4}-\d{2}-\d{2}), time (\d{2}:\d{2}),
	// baseline, count → 4 matches.
	expectedBase := float64(4) * evidenceWeight // 0.16

	const n = 1000
	var sum float64
	for i := 0; i < n; i++ {
		sum += computeConfidence(in)
	}
	avg := sum / n
	if math.Abs(avg-expectedBase) > 0.06 { // wider tolerance because noise is ±0.05
		t.Fatalf("evidence pattern scan: expected avg ~%.3f, got %.3f", expectedBase, avg)
	}
}

// TestCapEnforcement: inputs exceeding the caps (e.g. 20 tool calls) must not
// score higher than the capped maximum.
func TestCapEnforcement(t *testing.T) {
	capped := Input{
		ToolCalls:        toolCallCap,
		DistinctTools:    distinctCap,
		EvidencePatterns: ptr(evidenceCap),
		Iterations:       3,
	}
	uncapped := Input{
		ToolCalls:        100,
		DistinctTools:    50,
		EvidencePatterns: ptr(50),
		Iterations:       3,
	}

	const n = 500
	var sumCapped, sumUncapped float64
	for i := 0; i < n; i++ {
		sumCapped += computeConfidence(capped)
		sumUncapped += computeConfidence(uncapped)
	}
	avgCapped := sumCapped / n
	avgUncapped := sumUncapped / n

	// Both should converge to the same average since caps clip both equally.
	if math.Abs(avgCapped-avgUncapped) > 0.02 {
		t.Fatalf("cap enforcement: capped avg %.4f, uncapped avg %.4f — should be equal within noise",
			avgCapped, avgUncapped)
	}
}
