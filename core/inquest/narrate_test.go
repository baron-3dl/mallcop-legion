package inquest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// scriptedClient is a canned agent.Client: it returns a fixed text reply
// (or a transport error) regardless of the request, and records the last
// request it received for prompt-golden assertions. No network — this is the
// ONLY inference seam any core/inquest test touches.
type scriptedClient struct {
	reply   string
	err     error
	lastReq agent.MessagesRequest
	calls   int
}

func (c *scriptedClient) Messages(_ context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	c.calls++
	c.lastReq = req
	if c.err != nil {
		return agent.MessagesResponse{}, c.err
	}
	return agent.MessagesResponse{
		StopReason: "end_turn",
		Content:    []agent.ContentBlock{{Type: "text", Text: c.reply}},
	}, nil
}

// sequencedClient is a canned agent.Client that returns a DIFFERENT scripted
// reply per call, in order (replies[0] on the first call, replies[1] on the
// second, ...) — the fixture the intra-scan-disagreement tests need: a SINGLE
// RunAll call processing two co-occurring findings that land two DIFFERENT
// investigator verdicts, unlike scriptedClient's one fixed reply for every
// call. Calling past len(replies) repeats the last entry rather than
// panicking/indexing out of range.
type sequencedClient struct {
	replies []string
	calls   int
}

func (c *sequencedClient) Messages(_ context.Context, _ agent.MessagesRequest) (agent.MessagesResponse, error) {
	i := c.calls
	if i >= len(c.replies) {
		i = len(c.replies) - 1
	}
	c.calls++
	return agent.MessagesResponse{
		StopReason: "end_turn",
		Content:    []agent.ContentBlock{{Type: "text", Text: c.replies[i]}},
	}, nil
}

func sampleFinding() finding.Finding {
	return finding.Finding{
		ID: "finding-evt-1", Type: "assume_role", Severity: "critical",
		Actor: "forge-proxy", Reason: "AssumeRole into mallcop-bedrock-relay",
		Timestamp: time.Date(2026, 3, 1, 9, 2, 0, 0, time.UTC),
	}
}

// TestBuildUserMessage_Golden proves the user document is a single, fixed-shape
// JSON object carrying exactly {finding, resolution, evidence} — a golden
// snapshot of the document shape the fixed system prompt promises the model.
func TestBuildUserMessage_Golden(t *testing.T) {
	f := sampleFinding()
	res := ResolutionRef{Action: "escalate", Reason: "hard-constraint route: priv-escalation"}
	ev := Evidence{
		Identity: IdentityEvidence{Caller: "arn:aws:iam::111122223333:role/mallcop-bedrock-relay", FieldPaths: map[string]string{"caller": "payload.caller"}},
	}
	got, err := buildUserMessage(f, res, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	for _, want := range []string{
		`"finding":{"id":"finding-evt-1","type":"assume_role","severity":"critical","actor":"forge-proxy","reason":"AssumeRole into mallcop-bedrock-relay","timestamp":"2026-03-01T09:02:00Z"}`,
		`"resolution":{"action":"escalate","reason":"hard-constraint route: priv-escalation"}`,
		`"evidence":{"identity":{"caller":"arn:aws:iam::111122223333:role/mallcop-bedrock-relay"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("user document missing expected fragment:\n  want substring: %s\n  got: %s", want, got)
		}
	}
}

// TestSystemPrompt_RequiresGrantDirectionClause proves the fixed system prompt
// still carries the grantor/grantee/capability/direction requirement
// (mallcoppro-15e) — so a future prompt edit cannot silently drop the ACTION
// explanation contract that makes a trust/access-change finding intelligible.
func TestSystemPrompt_RequiresGrantDirectionClause(t *testing.T) {
	for _, want := range []string{"grantor", "grantee", "capability", "direction"} {
		if !strings.Contains(systemPrompt, want) {
			t.Errorf("systemPrompt no longer mentions %q — the grant-direction narrate contract was dropped", want)
		}
	}
}

// TestBuildUserMessage_Golden_WithGrantDirection proves the new
// grantor/grantee/capability identity fields serialize into the JSON user
// document so the narrate model actually receives the resolved direction. It is
// SEPARATE from TestBuildUserMessage_Golden (which must keep passing byte-for-
// byte with no grant fields present) precisely so the omitempty behavior of
// both the empty and populated cases is locked in.
func TestBuildUserMessage_Golden_WithGrantDirection(t *testing.T) {
	f := sampleFinding()
	res := ResolutionRef{Action: "escalate", Reason: "hard-constraint route: new-external-access"}
	ev := Evidence{
		Identity: IdentityEvidence{
			Grantor:    "arn:aws:iam::458526671706:role/mallcop-bedrock-relay",
			Grantee:    "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy",
			Capability: "can assume this role and act with its permissions",
			FieldPaths: map[string]string{"grantor": "finding.evidence"},
		},
	}
	got, err := buildUserMessage(f, res, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	for _, want := range []string{
		`"grantor":"arn:aws:iam::458526671706:role/mallcop-bedrock-relay"`,
		`"grantee":"arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"`,
		`"capability":"can assume this role and act with its permissions"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("user document missing grant-direction fragment:\n  want substring: %s\n  got: %s", want, got)
		}
	}
}

// TestSystemPrompt_RequiresOrgContextClause proves the fixed system prompt
// still carries the org-context naming instruction (mallcoppro-995) — a
// future prompt edit cannot silently drop the requirement to name an owned
// entity by its configured relationship, or the "informational, not
// dispositive" guard that keeps org-context from becoming a verdict override
// (the forbidden family-match/force-suppress anti-pattern).
func TestSystemPrompt_RequiresOrgContextClause(t *testing.T) {
	for _, want := range []string{"org_context", "OWNED", "relationship", "informational, not dispositive"} {
		if !strings.Contains(systemPrompt, want) {
			t.Errorf("systemPrompt no longer mentions %q — the org-context naming contract was dropped", want)
		}
	}
}

// TestBuildUserMessage_Golden_WithOrgContext proves the org_context evidence
// section serializes into the JSON user document so the narrate model
// actually receives the owned-entity relationship.
func TestBuildUserMessage_Golden_WithOrgContext(t *testing.T) {
	f := sampleFinding()
	res := ResolutionRef{Action: "escalate", Reason: "hard-constraint route: new-external-access"}
	ev := Evidence{
		OrgContext: OrgContextEvidence{
			CallerOwned: &OwnedMatch{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"},
		},
	}
	got, err := buildUserMessage(f, res, ev)
	if err != nil {
		t.Fatalf("buildUserMessage: %v", err)
	}
	want := `"org_context":{"caller_owned":{"match":"225635015146","name":"forge-proxy","relationship":"operator's own hourly inference relay"}}`
	if !strings.Contains(got, want) {
		t.Errorf("user document missing org_context fragment:\n  want substring: %s\n  got: %s", want, got)
	}
}

// TestNarrate_ValidReply proves a well-formed reply parses to StatusOK with
// the exact verdict/confidence/narrative.
func TestNarrate_ValidReply(t *testing.T) {
	c := &scriptedClient{reply: `{"verdict":"benign","confidence":0.85,"narrative":"forge-proxy assumed mallcop-bedrock-relay hourly, ~2min after each scan."}`}
	out := narrate(context.Background(), c, "investigate", 1024, "{}", Evidence{})
	if out.Status != StatusOK {
		t.Fatalf("Status = %q, want ok (err=%v)", out.Status, out.Err)
	}
	if out.Verdict != VerdictBenign || out.Confidence != 0.85 {
		t.Errorf("Verdict/Confidence = %v/%v", out.Verdict, out.Confidence)
	}
	if !strings.Contains(out.Narrative, "mallcop-bedrock-relay") {
		t.Errorf("Narrative = %q", out.Narrative)
	}
	if c.calls != 1 {
		t.Errorf("client called %d times, want exactly 1 (retries:0 — the hard one-call contract)", c.calls)
	}
	// The request carries the fixed system prompt and temp 0.
	if c.lastReq.System != systemPrompt {
		t.Error("request System prompt does not match the fixed systemPrompt constant")
	}
	if c.lastReq.Temperature == nil || *c.lastReq.Temperature != 0.0 {
		t.Errorf("request Temperature = %v, want pointer to 0.0", c.lastReq.Temperature)
	}
	if c.lastReq.Model != "investigate" {
		t.Errorf("request Model = %q, want %q", c.lastReq.Model, "investigate")
	}
}

// TestNarrate_ValidationMatrix drives every documented failure shape through
// narrate and asserts the correct narrative_status for each — no partial
// credit, no automatic retry (each case is exactly one client call).
func TestNarrate_ValidationMatrix(t *testing.T) {
	longNarrative := strings.Repeat("x", maxNarrativeBytes+1)
	cases := []struct {
		name  string
		reply string
	}{
		{"fenced", "```json\n{\"verdict\":\"benign\",\"confidence\":0.5,\"narrative\":\"looks fine, hourly cadence.\"}\n```"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "", 1024, "{}", Evidence{})
			if out.Status != StatusOK {
				t.Fatalf("Status = %q, want ok (err=%v) for reply %q", out.Status, out.Err, c.reply)
			}
		})
	}

	invalid := []struct {
		name  string
		reply string
	}{
		{"bad_enum", `{"verdict":"maybe","confidence":0.5,"narrative":"non-enum verdict"}`},
		{"confidence_out_of_range", `{"verdict":"benign","confidence":1.7,"narrative":"confidence too high"}`},
		{"empty_narrative", `{"verdict":"benign","confidence":0.5,"narrative":""}`},
		{"pure_garbage", `the weather is nice today, no JSON here at all`},
		{"oversized_narrative", `{"verdict":"benign","confidence":0.5,"narrative":"` + longNarrative + `"}`},
	}
	for _, c := range invalid {
		t.Run(c.name, func(t *testing.T) {
			client := &scriptedClient{reply: c.reply}
			out := narrate(context.Background(), client, "", 1024, "{}", Evidence{})
			if out.Status != StatusAbsentInvalidOutput {
				t.Fatalf("Status = %q, want absent-invalid-output for reply case %q", out.Status, c.name)
			}
			if out.Err == nil {
				t.Error("expected a non-nil Err explaining the validation failure")
			}
			if client.calls != 1 {
				t.Errorf("client called %d times, want exactly 1 (no automatic retry)", client.calls)
			}
		})
	}
}

// TestNarrate_TransportError proves a client.Messages error maps to
// absent-model-error, one call, no panic.
func TestNarrate_TransportError(t *testing.T) {
	client := &scriptedClient{err: context.DeadlineExceeded}
	out := narrate(context.Background(), client, "", 1024, "{}", Evidence{})
	if out.Status != StatusAbsentModelError {
		t.Fatalf("Status = %q, want absent-model-error", out.Status)
	}
	if client.calls != 1 {
		t.Errorf("client called %d times, want 1", client.calls)
	}
}

// TestParseModelReply_EmptyStringRejected covers the specific "confidence
// present but negative" edge alongside the documented [0,1] bound.
func TestParseModelReply_NegativeConfidenceRejected(t *testing.T) {
	_, _, _, err := parseModelReply(`{"verdict":"benign","confidence":-0.1,"narrative":"x"}`)
	if err == nil {
		t.Fatal("expected an error for negative confidence")
	}
}

// TestScrubCredentialShapes proves the belt-and-suspenders regex pass
// redacts an AKIA/ASIA-shaped key id and a sessionToken-labeled long base64
// run from narrative TEXT, independent of tools.GetRawEvent's structural
// scrub (see identity_test.go's end-to-end poisoned-payload proof).
func TestScrubCredentialShapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"akia_key",
			"the caller used access key AKIAIOSFODNN7EXAMPLE to authenticate",
			"the caller used access key [REDACTED] to authenticate",
		},
		{
			"asia_key",
			"temp credentials ASIAIOSFODNN7EXAMPLE were issued",
			"temp credentials [REDACTED] were issued",
		},
		{
			"session_token",
			`sessionToken: "FQoGZXIvYXdzEXAMPLE1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ" was present`,
			`sessionToken: "[REDACTED]" was present`,
		},
		{
			"clean_text_unchanged",
			"forge-proxy assumed mallcop-bedrock-relay hourly, ~2min after each scan.",
			"forge-proxy assumed mallcop-bedrock-relay hourly, ~2min after each scan.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scrubCredentialShapes(c.input)
			if got != c.want {
				t.Errorf("scrubCredentialShapes(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

// TestStripFences covers the fence-stripping helper directly for both the
// fenced and unfenced cases.
func TestStripFences(t *testing.T) {
	if got := stripFences("```json\n{\"a\":1}\n```"); got != `{"a":1}` {
		t.Errorf("stripFences(fenced) = %q", got)
	}
	if got := stripFences(`{"a":1}`); got != `{"a":1}` {
		t.Errorf("stripFences(unfenced) = %q", got)
	}
}
