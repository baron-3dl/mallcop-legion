package inquest

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func escalatedFor(id, actor string) EscalatedFinding {
	return EscalatedFinding{
		Finding:    finding.Finding{ID: id, Actor: actor, Type: "assume_role", Timestamp: time.Now()},
		Resolution: ResolutionRef{Action: "escalate", Reason: "test"},
	}
}

func okConfig() Config {
	return Config{Enabled: true, MaxPerScan: 10, MaxTokens: 1024}
}

// readRecord reads back the committed record for findingID, failing the test
// if it's missing or malformed.
func readRecord(t *testing.T, in Input, findingID string) Record {
	t.Helper()
	data, err := in.Store.ReadSnapshot(recordPath(findingID))
	if err != nil {
		t.Fatalf("ReadSnapshot(%s): %v", findingID, err)
	}
	if len(data) == 0 {
		t.Fatalf("no record found for %s", findingID)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unmarshal record %s: %v", findingID, err)
	}
	return rec
}

// TestRunAll_Disabled proves the off-switch writes NO records at all — not
// even evidence-only — and touches the store with zero reads/writes.
func TestRunAll_Disabled(t *testing.T) {
	s := newTempStore(t)
	in := Input{
		Store:    s,
		Client:   &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"should never be called"}`},
		Findings: []EscalatedFinding{escalatedFor("finding-1", "actor-a")},
		Config:   Config{Enabled: false},
	}
	out := RunAll(context.Background(), in)
	if out.Investigated != 0 || out.Degraded != 0 || out.Skipped != 0 {
		t.Fatalf("Outcome = %+v, want all-zero", out)
	}
	if data, err := s.ReadSnapshot(recordPath("finding-1")); err != nil || len(data) != 0 {
		t.Fatalf("expected no record written when disabled, got data=%q err=%v", data, err)
	}
}

// TestRunAll_NoClient proves a nil Client degrades to absent-no-client
// evidence-only records, no panic, no call attempted.
func TestRunAll_NoClient(t *testing.T) {
	s := newTempStore(t)
	in := Input{
		Store:    s,
		Client:   nil,
		Findings: []EscalatedFinding{escalatedFor("finding-1", "actor-a")},
		Config:   okConfig(),
	}
	out := RunAll(context.Background(), in)
	if out.Investigated != 0 || out.Degraded != 1 {
		t.Fatalf("Outcome = %+v, want Degraded=1", out)
	}
	rec := readRecord(t, in, "finding-1")
	if rec.NarrativeStatus != StatusAbsentNoClient {
		t.Errorf("NarrativeStatus = %q, want %q", rec.NarrativeStatus, StatusAbsentNoClient)
	}
	if rec.Role != "evidence" || rec.Verdict != VerdictUnassessed {
		t.Errorf("Role/Verdict = %q/%q, want evidence/unassessed", rec.Role, rec.Verdict)
	}
}

// TestRunAll_SuccessfulInvestigation proves the happy path: one escalated
// finding, a valid model reply, a committed record with narrative_status ok
// and Investigated==1.
func TestRunAll_SuccessfulInvestigation(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"forge-proxy assumed mallcop-bedrock-relay hourly."}`}
	in := Input{
		Store:    s,
		Client:   client,
		Findings: []EscalatedFinding{escalatedFor("finding-1", "actor-a")},
		Config:   okConfig(),
	}
	out := RunAll(context.Background(), in)
	if out.Investigated != 1 || out.Degraded != 0 {
		t.Fatalf("Outcome = %+v, want Investigated=1", out)
	}
	rec := readRecord(t, in, "finding-1")
	if rec.NarrativeStatus != StatusOK || rec.Verdict != VerdictBenign {
		t.Errorf("rec = %+v", rec)
	}
	if client.calls != 1 {
		t.Errorf("client called %d times, want 1", client.calls)
	}
}

// TestRunAll_GrantDirectionFlowsToModel is the end-to-end proof (mallcoppro-15e)
// that the resolved trust direction reaches the ACTUAL request sent to the model,
// not just the pure resolveGrantDirection function in isolation. A
// new-external-access finding with a realistic AWS cross-account trust_added
// Evidence blob is run through RunAll; the scripted client records the user
// document it received, and we assert the FLIPPED grantor/grantee (the assumed
// role is the grantor, the calling principal is the grantee) appear in that
// document's JSON body.
func TestRunAll_GrantDirectionFlowsToModel(t *testing.T) {
	s := newTempStore(t)
	const forgeProxy = "arn:aws:sts::225635015146:assumed-role/forge-proxy-bedrock-role/forge-proxy"
	const relay = "arn:aws:iam::458526671706:role/mallcop-bedrock-relay"

	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"mallcop-bedrock-relay granted forge-proxy assume-role access; operational relay."}`}
	ef := EscalatedFinding{
		Finding: finding.Finding{
			ID: "finding-evt-trust", Actor: forgeProxy, Type: "new-external-access",
			Timestamp: time.Now(),
			Evidence:  json.RawMessage(`{"actor":"` + forgeProxy + `","grantee":"` + relay + `","member":"` + relay + `","event_type":"trust_added"}`),
		},
		Resolution: ResolutionRef{Action: "escalate", Reason: "test"},
	}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{ef}, Config: okConfig()}

	out := RunAll(context.Background(), in)
	if out.Investigated != 1 {
		t.Fatalf("Outcome = %+v, want Investigated=1", out)
	}
	if client.calls != 1 {
		t.Fatalf("client called %d times, want 1", client.calls)
	}
	if len(client.lastReq.Messages) == 0 || len(client.lastReq.Messages[0].Content) == 0 {
		t.Fatal("no user message recorded on the scripted client")
	}
	userDoc := client.lastReq.Messages[0].Content[0].Text
	if !strings.Contains(userDoc, `"grantor":"`+relay+`"`) {
		t.Errorf("user document does not carry the FLIPPED grantor (assumed role %q):\n%s", relay, userDoc)
	}
	if !strings.Contains(userDoc, `"grantee":"`+forgeProxy+`"`) {
		t.Errorf("user document does not carry the FLIPPED grantee (calling principal %q):\n%s", forgeProxy, userDoc)
	}
	if !strings.Contains(userDoc, `"capability":`) {
		t.Errorf("user document does not carry a capability field:\n%s", userDoc)
	}
}

// TestRunAll_IdempotencyDecisionTable exercises the three documented cases:
// (a) record exists + ok + current schema -> ok-skip (zero calls, zero
// writes — the WriteSnapshot commit SHA is unchanged); (b) record exists but
// degraded -> refresh (one call, CreatedAt preserved); (c) record absent ->
// new (one call, fresh CreatedAt).
func TestRunAll_IdempotencyDecisionTable(t *testing.T) {
	t.Run("ok_skip", func(t *testing.T) {
		s := newTempStore(t)
		client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"first pass narrative."}`}
		in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
		first := RunAll(context.Background(), in)
		if first.Investigated != 1 {
			t.Fatalf("first run Outcome = %+v, want Investigated=1", first)
		}
		firstRec := readRecord(t, in, "finding-1")
		beforeSHA := headSHA(t, s)

		second := RunAll(context.Background(), in)
		if second.Skipped != 1 || second.Investigated != 0 || second.Degraded != 0 {
			t.Fatalf("second run Outcome = %+v, want Skipped=1", second)
		}
		if client.calls != 1 {
			t.Errorf("client called %d times across two runs, want 1 (ok-skip makes zero additional calls)", client.calls)
		}
		afterSHA := headSHA(t, s)
		if beforeSHA != afterSHA {
			t.Errorf("ok-skip produced a new commit (%s -> %s); WriteSnapshot's byte-identical no-op should have made this call a pure read", beforeSHA, afterSHA)
		}
		secondRec := readRecord(t, in, "finding-1")
		if secondRec.CreatedAt != firstRec.CreatedAt || secondRec.UpdatedAt != firstRec.UpdatedAt {
			t.Errorf("ok-skip must not touch the record: first=%+v second=%+v", firstRec, secondRec)
		}
	})

	t.Run("degraded_refresh", func(t *testing.T) {
		s := newTempStore(t)
		client := &scriptedClient{reply: "not json at all"} // -> absent-invalid-output
		in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
		first := RunAll(context.Background(), in)
		if first.Degraded != 1 {
			t.Fatalf("first run Outcome = %+v, want Degraded=1", first)
		}
		firstRec := readRecord(t, in, "finding-1")
		if firstRec.NarrativeStatus != StatusAbsentInvalidOutput {
			t.Fatalf("first run NarrativeStatus = %q", firstRec.NarrativeStatus)
		}

		// Refresh: this time the model succeeds. Sleep past the 1s resolution
		// of the RFC3339 UpdatedAt stamp so the refresh is provably a NEW
		// timestamp, not a coincidentally-identical one from running fast.
		time.Sleep(1100 * time.Millisecond)
		client.reply = `{"verdict":"suspicious","confidence":0.6,"narrative":"refreshed narrative on retry."}`
		second := RunAll(context.Background(), in)
		if second.Investigated != 1 || second.Skipped != 0 {
			t.Fatalf("second run Outcome = %+v, want Investigated=1 (degraded records are refresh-eligible)", second)
		}
		if client.calls != 2 {
			t.Errorf("client called %d times, want 2 (one per run — degraded is NOT skipped)", client.calls)
		}
		secondRec := readRecord(t, in, "finding-1")
		if secondRec.NarrativeStatus != StatusOK || secondRec.Verdict != VerdictSuspicious {
			t.Errorf("refreshed rec = %+v", secondRec)
		}
		if secondRec.CreatedAt != firstRec.CreatedAt {
			t.Errorf("CreatedAt changed on refresh: first=%q second=%q, want preserved", firstRec.CreatedAt, secondRec.CreatedAt)
		}
		if secondRec.UpdatedAt == firstRec.UpdatedAt {
			t.Errorf("UpdatedAt did not change on refresh")
		}
	})

	t.Run("absent_create", func(t *testing.T) {
		s := newTempStore(t)
		if data, err := s.ReadSnapshot(recordPath("finding-1")); err != nil || len(data) != 0 {
			t.Fatalf("precondition: expected no existing record, got %q / %v", data, err)
		}
		client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"brand new record."}`}
		in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
		out := RunAll(context.Background(), in)
		if out.Investigated != 1 {
			t.Fatalf("Outcome = %+v, want Investigated=1", out)
		}
		if client.calls != 1 {
			t.Errorf("client called %d times, want 1", client.calls)
		}
	})
}

// --- Case-keyed recurrence (mallcoppro-42e) --------------------------------

// escalatedForCase is escalatedFor plus a resolved CaseID — mirroring what
// core/pipeline threads onto EscalatedFinding.CaseID via the SAME exported
// core/cases.CaseID hash (never re-derived here — the caller just needs SOME
// stable string a real caseID would also produce; the exact hash bytes don't
// matter to these unit tests, only that two calls sharing caseID collide onto
// the SAME record and a fresh CaseID produces a different one).
func escalatedForCase(id, actor, caseID string) EscalatedFinding {
	ef := escalatedFor(id, actor)
	ef.CaseID = caseID
	return ef
}

// TestRunAll_CaseKeyed_RefireRefreshesSharedRecord proves the mallcoppro-42e
// migration end to end at the RunAll level: two SEPARATE RunAll calls (two
// "scans"), each escalating a DIFFERENT finding ID but the SAME CaseID (a
// refire of the same recurring case), write to exactly ONE on-disk record —
// investigations/<caseID>.json — refreshed in place: UpdatedAt advances,
// CreatedAt is preserved from the FIRST occurrence, and FindingID tracks the
// most recent contributing finding. No investigations/<finding-id>.json is
// ever written for either finding once CaseID is set.
func TestRunAll_CaseKeyed_RefireRefreshesSharedRecord(t *testing.T) {
	s := newTempStore(t)
	const caseID = "case-abc123"
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"first occurrence, looks routine."}`}

	first := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedForCase("finding-1", "actor-a", caseID)}, Config: okConfig()}
	out1 := RunAll(context.Background(), first)
	if out1.Investigated != 1 {
		t.Fatalf("scan 1 Outcome = %+v, want Investigated=1", out1)
	}
	rec1 := readRecord(t, first, caseID)
	if rec1.FindingID != "finding-1" || rec1.CaseID != caseID {
		t.Fatalf("scan 1 record = %+v, want FindingID=finding-1 CaseID=%s", rec1, caseID)
	}

	// Neither finding's own finding-ID path ever gets a record once CaseID is set.
	if data, err := s.ReadSnapshot(recordPath("finding-1")); err != nil || len(data) != 0 {
		t.Fatalf("expected no per-finding record at investigations/finding-1.json, got data=%q err=%v", data, err)
	}

	time.Sleep(1100 * time.Millisecond) // past RFC3339's 1s resolution
	client.reply = `{"verdict":"benign","confidence":0.85,"narrative":"recurred again, same read."}`
	second := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedForCase("finding-2", "actor-a", caseID)}, Config: okConfig()}
	out2 := RunAll(context.Background(), second)
	if out2.Investigated != 1 || out2.Skipped != 0 {
		t.Fatalf("scan 2 (refire, DIFFERENT finding, SAME case) Outcome = %+v, want Investigated=1 (a refire is never skipped)", out2)
	}
	if client.calls != 2 {
		t.Fatalf("client called %d times across 2 scans, want 2 (each refire makes its own call)", client.calls)
	}

	rec2 := readRecord(t, second, caseID)
	if rec2.FindingID != "finding-2" {
		t.Errorf("rec2.FindingID = %q, want finding-2 (the most recent contributing finding)", rec2.FindingID)
	}
	if rec2.CreatedAt != rec1.CreatedAt {
		t.Errorf("CreatedAt changed on refire: scan1=%q scan2=%q, want preserved (case's first occurrence)", rec1.CreatedAt, rec2.CreatedAt)
	}
	if rec2.UpdatedAt == rec1.UpdatedAt {
		t.Errorf("UpdatedAt did not advance on refire")
	}
	if data, err := s.ReadSnapshot(recordPath("finding-2")); err != nil || len(data) != 0 {
		t.Fatalf("expected no per-finding record at investigations/finding-2.json, got data=%q err=%v", data, err)
	}

	// Exactly one investigations/*.json record exists for this case across
	// both scans — no duplicate, no second file under either finding's ID.
	if data, err := s.ReadSnapshot(recordPath(caseID)); err != nil || len(data) == 0 {
		t.Fatalf("expected exactly one record at investigations/%s.json", caseID)
	}
}

// TestRunAll_CaseKeyed_VerdictFlipFlagged proves the recurrence design's other
// half: a refire whose fresh pass lands a MATERIALLY DIFFERENT trusted verdict
// (benign -> threat) WRITES the new verdict (never averages, never suppresses
// it — Verdict/Confidence/Narrative are the fresh pass's own values) AND flags
// the change: structurally (Record.VerdictFlip) and in-band (a prefix on the
// narrative itself), so a reader of just this one JSON document sees the flip
// without having to diff historical copies.
func TestRunAll_CaseKeyed_VerdictFlipFlagged(t *testing.T) {
	s := newTempStore(t)
	const caseID = "case-flip1"
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"looked routine at first."}`}

	first := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedForCase("finding-1", "actor-a", caseID)}, Config: okConfig()}
	if out := RunAll(context.Background(), first); out.Investigated != 1 {
		t.Fatalf("scan 1 Outcome = %+v, want Investigated=1", out)
	}
	rec1 := readRecord(t, first, caseID)
	if rec1.Verdict != VerdictBenign || rec1.VerdictFlip != nil {
		t.Fatalf("scan 1 record = %+v, want Verdict=benign, VerdictFlip=nil (nothing to flip against yet)", rec1)
	}

	client.reply = `{"verdict":"threat","confidence":0.95,"narrative":"recurrence pattern now reveals active compromise."}`
	second := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedForCase("finding-2", "actor-a", caseID)}, Config: okConfig()}
	if out := RunAll(context.Background(), second); out.Investigated != 1 {
		t.Fatalf("scan 2 (refire, flipped verdict) Outcome = %+v, want Investigated=1", out)
	}

	rec2 := readRecord(t, second, caseID)
	if rec2.Verdict != VerdictThreat {
		t.Fatalf("rec2.Verdict = %q, want threat — the FRESH verdict is written, never averaged or suppressed", rec2.Verdict)
	}
	if rec2.VerdictFlip == nil {
		t.Fatal("rec2.VerdictFlip = nil, want a flip flag (benign -> threat)")
	}
	if rec2.VerdictFlip.From != VerdictBenign || rec2.VerdictFlip.To != VerdictThreat {
		t.Errorf("VerdictFlip = %+v, want {From:benign To:threat}", rec2.VerdictFlip)
	}
	if !strings.Contains(rec2.Narrative, "VERDICT FLIP") {
		t.Errorf("Narrative = %q, want an in-band flip flag", rec2.Narrative)
	}
	if !strings.Contains(rec2.Narrative, "active compromise") {
		t.Errorf("Narrative = %q, want the model's own fresh narrative preserved, not replaced", rec2.Narrative)
	}
}

// TestRunAll_Force_BypassesIdempotencySkip proves the low-confidence
// deeper-pass retrigger (mallcoppro-09a): a finding whose EXISTING record is
// already ok + current-schema (the case the normal path SKIPS) IS re-investigated
// (a fresh metered call, a refreshed record, CreatedAt preserved) when Input.Force
// is set — and the normal Force==false path over the identical record is still
// skipped, unchanged.
func TestRunAll_Force_BypassesIdempotencySkip(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.4,"narrative":"first, low-confidence pass."}`}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}

	// Pass 1: writes an ok record.
	if out := RunAll(context.Background(), in); out.Investigated != 1 {
		t.Fatalf("pass 1 Outcome = %+v, want Investigated=1", out)
	}
	firstRec := readRecord(t, in, "finding-1")

	// Control: a normal (Force==false) re-run over the SAME ok record is SKIPPED —
	// zero additional calls (the existing idempotency contract, unchanged).
	if out := RunAll(context.Background(), in); out.Skipped != 1 || out.Investigated != 0 {
		t.Fatalf("Force==false re-run Outcome = %+v, want Skipped=1 (idempotency unchanged)", out)
	}
	if client.calls != 1 {
		t.Fatalf("Force==false re-run made an extra call; total calls = %d, want 1", client.calls)
	}

	// Sleep past the 1s RFC3339 resolution so a refreshed UpdatedAt is provably new.
	time.Sleep(1100 * time.Millisecond)
	client.reply = `{"verdict":"benign","confidence":0.9,"narrative":"deeper pass, now confident."}`
	forced := in
	forced.Force = true
	if out := RunAll(context.Background(), forced); out.Investigated != 1 || out.Skipped != 0 {
		t.Fatalf("Force==true Outcome = %+v, want Investigated=1 (skip bypassed)", out)
	}
	if client.calls != 2 {
		t.Fatalf("Force==true must make a fresh call; total calls = %d, want 2", client.calls)
	}
	secondRec := readRecord(t, in, "finding-1")
	if secondRec.Confidence != 0.9 {
		t.Errorf("forced deeper pass Confidence = %v, want 0.9 (record refreshed with the new reply)", secondRec.Confidence)
	}
	if secondRec.CreatedAt != firstRec.CreatedAt {
		t.Errorf("forced refresh reset CreatedAt: first=%q second=%q, want preserved", firstRec.CreatedAt, secondRec.CreatedAt)
	}
	if secondRec.UpdatedAt == firstRec.UpdatedAt {
		t.Errorf("forced refresh did not bump UpdatedAt")
	}
}

// TestRunAll_Force_OverBudgetDoesNotOverwriteExistingOk proves the review fix
// for mallcoppro-09a's overwrite regression: when a Force re-pass (the
// low-confidence deeper-investigation retrigger) runs over its OWN separate
// budget and a finding falls past that budget, processOne must NOT clobber
// the finding's prior good "ok" record with a StatusAbsentBudget/unassessed
// one. Concrete scenario from the review: two findings already have ok
// records; a Force pass with a budget of 1 lets only the first (sorted by
// ID) get a fresh call — the second must keep its original verdict,
// confidence, narrative, and NarrativeStatus byte-for-byte.
func TestRunAll_Force_OverBudgetDoesNotOverwriteExistingOk(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.3,"narrative":"first pass, benign, low-confidence."}`}
	findings := []EscalatedFinding{escalatedFor("finding-00", "a"), escalatedFor("finding-01", "a")}
	in := Input{Store: s, Client: client, Findings: findings, Config: okConfig()}

	// Pass 1: both findings get an ok record.
	if out := RunAll(context.Background(), in); out.Investigated != 2 {
		t.Fatalf("pass 1 Outcome = %+v, want Investigated=2", out)
	}
	before00 := readRecord(t, in, "finding-00")
	before01 := readRecord(t, in, "finding-01")
	if before00.NarrativeStatus != StatusOK || before01.NarrativeStatus != StatusOK {
		t.Fatalf("pass 1 records not both ok: %+v / %+v", before00, before01)
	}

	// Pass 2: Force=true, budget of 1 — finding-00 (sorted first) gets the
	// fresh call, finding-01 falls past budget in processOne's budget branch.
	client.reply = `{"verdict":"suspicious","confidence":0.95,"narrative":"deeper pass, now confident."}`
	forced := in
	forced.Force = true
	forced.Config.MaxPerScan = 1
	out := RunAll(context.Background(), forced)
	if out.Investigated != 1 {
		t.Errorf("Investigated = %d, want 1 (finding-00 got the sole budget slot)", out.Investigated)
	}
	if out.Degraded != 1 {
		t.Errorf("Degraded = %d, want 1 (finding-01's failed Force re-pass, tallied not silent)", out.Degraded)
	}
	if client.calls != 3 {
		t.Errorf("client called %d times, want 3 (2 from pass 1, 1 from the budgeted Force pass)", client.calls)
	}

	after00 := readRecord(t, in, "finding-00")
	if after00.NarrativeStatus != StatusOK || after00.Confidence != 0.95 {
		t.Errorf("finding-00 (within budget) = %+v, want refreshed ok/0.95", after00)
	}

	after01 := readRecord(t, in, "finding-01")
	if after01.NarrativeStatus != StatusOK {
		t.Fatalf("finding-01 (over Force budget) NarrativeStatus = %q, want %q — a failed Force re-pass must never overwrite a prior good record", after01.NarrativeStatus, StatusOK)
	}
	if after01.Verdict != before01.Verdict || after01.Confidence != before01.Confidence || after01.Narrative != before01.Narrative || after01.UpdatedAt != before01.UpdatedAt {
		t.Errorf("finding-01 record was mutated by the failed Force re-pass:\n before=%+v\n after=%+v", before01, after01)
	}
}

// TestRunAll_Force_ModelErrorDoesNotOverwriteExistingOk proves the same
// overwrite guard fires on ANY deep-pass failure mode, not just the budget
// branch — a transient model-call error (timeout/transport failure) during a
// Force re-pass must also leave a prior ok record untouched rather than
// downgrading it to an absent-model-error record.
func TestRunAll_Force_ModelErrorDoesNotOverwriteExistingOk(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.3,"narrative":"first pass, benign, low-confidence."}`}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}

	if out := RunAll(context.Background(), in); out.Investigated != 1 {
		t.Fatalf("pass 1 Outcome = %+v, want Investigated=1", out)
	}
	before := readRecord(t, in, "finding-1")

	client.reply = ""
	client.err = context.DeadlineExceeded
	forced := in
	forced.Force = true
	out := RunAll(context.Background(), forced)
	if out.Investigated != 0 || out.Degraded != 1 {
		t.Fatalf("Force model-error Outcome = %+v, want Investigated=0/Degraded=1", out)
	}

	after := readRecord(t, in, "finding-1")
	if after.NarrativeStatus != StatusOK {
		t.Fatalf("NarrativeStatus = %q, want %q — a failed Force re-pass (model error) must never overwrite a prior good record", after.NarrativeStatus, StatusOK)
	}
	if after.Verdict != before.Verdict || after.Confidence != before.Confidence || after.Narrative != before.Narrative || after.UpdatedAt != before.UpdatedAt {
		t.Errorf("record was mutated by the failed Force re-pass:\n before=%+v\n after=%+v", before, after)
	}
}

// perFindingClient returns a transport error for any request whose prompt
// mentions the finding ID in errFor, and the canned reply for every other
// finding — the seam TestRunAll_FreshOKIDs_ExcludeFailedForcePass uses to make
// ONE Force pass land a fresh verdict for one finding while the other's deep
// call fails. reply/errFor are read live per call so the test can flip them
// between passes.
type perFindingClient struct {
	reply  string
	errFor string
	calls  int
}

func (c *perFindingClient) Messages(_ context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	c.calls++
	var text string
	if len(req.Messages) > 0 && len(req.Messages[0].Content) > 0 {
		text = req.Messages[0].Content[0].Text
	}
	if c.errFor != "" && strings.Contains(text, c.errFor) {
		return agent.MessagesResponse{}, context.DeadlineExceeded
	}
	return agent.MessagesResponse{
		StopReason: "end_turn",
		Content:    []agent.ContentBlock{{Type: "text", Text: c.reply}},
	}, nil
}

// TestRunAll_FreshOKIDs_ExcludeFailedForcePass proves Outcome.FreshOKIDs is the
// precise per-finding companion to Investigated that the low-confidence re-vote
// (core/pipeline, mallcoppro-09a review finding) keys off: it lists ONLY the
// findings whose fresh "ok" verdict actually landed AND persisted this run. A
// Force re-pass whose fresh pass FAILED (here: model error) keeps the finding's
// prior first-pass record and must NOT appear in FreshOKIDs — otherwise the
// re-vote would run on first-pass evidence relabeled as a deeper investigation.
// Two findings share one Force pass: one lands a fresh ok verdict, the other's
// deep call errors and is dropped from the set.
func TestRunAll_FreshOKIDs_ExcludeFailedForcePass(t *testing.T) {
	s := newTempStore(t)
	client := &perFindingClient{reply: `{"verdict":"benign","confidence":0.3,"narrative":"first pass, low-confidence."}`}
	findings := []EscalatedFinding{escalatedFor("finding-00", "a"), escalatedFor("finding-01", "a")}
	in := Input{Store: s, Client: client, Findings: findings, Config: okConfig()}

	// Pass 1: both findings get a fresh ok record — both must be in FreshOKIDs.
	out := RunAll(context.Background(), in)
	if out.Investigated != 2 {
		t.Fatalf("pass 1 Outcome = %+v, want Investigated=2", out)
	}
	if len(out.FreshOKIDs) != 2 {
		t.Fatalf("pass 1 FreshOKIDs = %v, want both findings (len 2, == Investigated)", out.FreshOKIDs)
	}

	// Pass 2 (Force): finding-00's deep call lands a fresh ok verdict;
	// finding-01's deep call errors, so its prior ok record is preserved (the
	// overwrite guard) and it must be ABSENT from FreshOKIDs.
	client.errFor = "finding-01"
	client.reply = `{"verdict":"benign","confidence":0.95,"narrative":"deeper pass, now confident."}`
	forced := in
	forced.Force = true
	out = RunAll(context.Background(), forced)
	if out.Investigated != 1 || out.Degraded != 1 {
		t.Fatalf("Force pass Outcome = %+v, want Investigated=1/Degraded=1", out)
	}
	if len(out.FreshOKIDs) != 1 || out.FreshOKIDs[0] != "finding-00" {
		t.Fatalf("FreshOKIDs = %v, want exactly [finding-00] — the failed-deep-pass finding must NOT be reported as a fresh verdict", out.FreshOKIDs)
	}
}

// TestAttachRevote_AdditiveAndReadRecord proves the exported ReadRecord +
// AttachRevote path (mallcoppro-09a): a re-vote outcome is attached to an
// existing investigation record WITHOUT touching its verdict/confidence/narrative
// or its Resolution disposition (the consensus invariant — the escalation stands;
// the re-vote is a second opinion), and AttachRevote on an absent record is an
// error (a re-vote can only attach to a finding that was investigated).
func TestAttachRevote_AdditiveAndReadRecord(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"suspicious","confidence":0.4,"narrative":"shaky verdict."}`}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
	if out := RunAll(context.Background(), in); out.Investigated != 1 {
		t.Fatalf("Outcome = %+v, want Investigated=1", out)
	}
	before := readRecord(t, in, "finding-1")

	// Absent-record attach is an error.
	if err := AttachRevote(s, "finding-does-not-exist", RevoteOutcome{Triggered: true}); err == nil {
		t.Fatal("AttachRevote on an absent record must error")
	}

	outcome := RevoteOutcome{Triggered: true, ResolveVotes: 3, TotalVotes: 3, UnanimousResolve: true, Reason: "unanimous"}
	if err := AttachRevote(s, "finding-1", outcome); err != nil {
		t.Fatalf("AttachRevote: %v", err)
	}
	after := readRecord(t, in, "finding-1")
	if after.Revote == nil || *after.Revote != outcome {
		t.Fatalf("Revote = %+v, want %+v", after.Revote, outcome)
	}
	// The disposition + verdict fields are untouched — additive only.
	if after.Verdict != before.Verdict || after.Confidence != before.Confidence ||
		after.Narrative != before.Narrative || after.NarrativeStatus != before.NarrativeStatus ||
		after.Resolution != before.Resolution || after.CreatedAt != before.CreatedAt {
		t.Errorf("AttachRevote mutated a non-Revote field:\n before=%+v\n after=%+v", before, after)
	}
	// ReadRecord's found flag: true for a real record, false (no error) for an absent one.
	if _, found, err := ReadRecord(s, "finding-1"); err != nil || !found {
		t.Errorf("ReadRecord(existing) = found=%v err=%v, want true/nil", found, err)
	}
	if _, found, err := ReadRecord(s, "nope"); err != nil || found {
		t.Errorf("ReadRecord(absent) = found=%v err=%v, want false/nil", found, err)
	}
}

// TestRunAll_BudgetGate proves 12 escalations against a cap of 10 produce
// exactly 10 model calls and 2 absent-budget records — deterministic by
// finding-ID sort order, so the SAME 10 findings get the call every run.
func TestRunAll_BudgetGate(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.5,"narrative":"budget-gate narrative text."}`}

	var findings []EscalatedFinding
	for i := 0; i < 12; i++ {
		findings = append(findings, escalatedFor(fmt.Sprintf("finding-%02d", i), "a"))
	}
	in := Input{Store: s, Client: client, Findings: findings, Config: Config{Enabled: true, MaxPerScan: 10, MaxTokens: 1024}}

	out := RunAll(context.Background(), in)
	if out.Investigated != 10 {
		t.Errorf("Investigated = %d, want 10", out.Investigated)
	}
	if out.Degraded != 2 {
		t.Errorf("Degraded = %d, want 2", out.Degraded)
	}
	if client.calls != 10 {
		t.Errorf("client called %d times, want exactly 10 (the budget cap)", client.calls)
	}

	// The first 10 by sorted finding ID got investigated; the last 2 are
	// absent-budget.
	for i := 0; i < 10; i++ {
		rec := readRecord(t, in, fmt.Sprintf("finding-%02d", i))
		if rec.NarrativeStatus != StatusOK {
			t.Errorf("finding-%02d NarrativeStatus = %q, want ok", i, rec.NarrativeStatus)
		}
	}
	for i := 10; i < 12; i++ {
		rec := readRecord(t, in, fmt.Sprintf("finding-%02d", i))
		if rec.NarrativeStatus != StatusAbsentBudget {
			t.Errorf("finding-%02d NarrativeStatus = %q, want absent-budget", i, rec.NarrativeStatus)
		}
	}
}

// TestRunAll_BudgetGate_DefaultAppliesWhenUnset proves MaxPerScan<=0 falls
// back to defaultMaxPerScan (10), not 0/unbounded.
func TestRunAll_BudgetGate_DefaultAppliesWhenUnset(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.5,"narrative":"default budget narrative."}`}
	var findings []EscalatedFinding
	for i := 0; i < 12; i++ {
		findings = append(findings, escalatedFor(fmt.Sprintf("finding-%02d", i), "a"))
	}
	in := Input{Store: s, Client: client, Findings: findings, Config: Config{Enabled: true, MaxTokens: 1024}} // MaxPerScan unset
	out := RunAll(context.Background(), in)
	if out.Investigated != defaultMaxPerScan {
		t.Errorf("Investigated = %d, want default %d", out.Investigated, defaultMaxPerScan)
	}
}

// panickingClient is an agent.Client that panics inside Messages when the
// request's user document mentions "finding-panics", and otherwise replies
// with okReply — proving processOne's panic guard degrades ONLY the
// panicking finding while every other finding in the same RunAll call still
// completes normally.
type panickingClient struct {
	okReply string
}

func (c *panickingClient) Messages(_ context.Context, req agent.MessagesRequest) (agent.MessagesResponse, error) {
	var text string
	if len(req.Messages) > 0 && len(req.Messages[0].Content) > 0 {
		text = req.Messages[0].Content[0].Text
	}
	if strings.Contains(text, "finding-panics") {
		panic("simulated model client panic")
	}
	return agent.MessagesResponse{
		StopReason: "end_turn",
		Content:    []agent.ContentBlock{{Type: "text", Text: c.okReply}},
	}, nil
}

// TestRunAll_PanicGuard proves a panic during the model call (or anywhere in
// per-finding processing) degrades ONLY that finding and RunAll still
// completes and reports every OTHER finding correctly.
func TestRunAll_PanicGuard(t *testing.T) {
	s := newTempStore(t)
	client := &panickingClient{okReply: `{"verdict":"benign","confidence":0.5,"narrative":"the survivor's narrative."}`}
	in := Input{
		Store:  s,
		Client: client,
		Findings: []EscalatedFinding{
			escalatedFor("finding-panics", "a"),
			escalatedFor("finding-survives", "b"),
		},
		Config: okConfig(),
	}
	out := RunAll(context.Background(), in)
	// One finding panicked (degraded), one succeeded (investigated).
	if out.Investigated != 1 {
		t.Errorf("Investigated = %d, want 1 (the survivor)", out.Investigated)
	}
	if out.Degraded != 1 {
		t.Errorf("Degraded = %d, want 1 (the panicker)", out.Degraded)
	}
	if len(out.Errors) == 0 {
		t.Error("expected a non-empty Errors entry for the panic")
	}

	panicked := readRecord(t, in, "finding-panics")
	if panicked.NarrativeStatus != StatusAbsentModelError {
		t.Errorf("panicked finding NarrativeStatus = %q, want %q", panicked.NarrativeStatus, StatusAbsentModelError)
	}
	survived := readRecord(t, in, "finding-survives")
	if survived.NarrativeStatus != StatusOK {
		t.Errorf("survivor NarrativeStatus = %q, want ok", survived.NarrativeStatus)
	}
}

// TestRunAll_NilStore proves a nil store degrades gracefully (an error line,
// zero panics) rather than dereferencing nil.
func TestRunAll_NilStore(t *testing.T) {
	in := Input{
		Store:    nil,
		Client:   &scriptedClient{reply: `{"verdict":"benign","confidence":0.5,"narrative":"x"}`},
		Findings: []EscalatedFinding{escalatedFor("finding-1", "a")},
		Config:   okConfig(),
	}
	out := RunAll(context.Background(), in)
	if len(out.Errors) == 0 {
		t.Error("expected a non-empty Errors entry for a nil store")
	}
	if out.Investigated != 0 || out.Degraded != 0 {
		t.Errorf("Outcome = %+v, want zero counts (nothing could be processed)", out)
	}
}

// hangingClient blocks in Messages until ctx is done, then returns ctx.Err()
// — a stub for "the model never replies", proving RunAll's per-call
// CallTimeout actually bounds the wait rather than hanging the whole scan.
type hangingClient struct{}

func (hangingClient) Messages(ctx context.Context, _ agent.MessagesRequest) (agent.MessagesResponse, error) {
	<-ctx.Done()
	return agent.MessagesResponse{}, ctx.Err()
}

// TestRunAll_HungClientTimesOutAndScanCompletes proves a client that never
// replies is bounded by Config.CallTimeout (driven short here so the test
// doesn't wait 60 real seconds) — RunAll still returns promptly with a
// degraded record, never blocking the caller past the deadline.
func TestRunAll_HungClientTimesOutAndScanCompletes(t *testing.T) {
	s := newTempStore(t)
	in := Input{
		Store:    s,
		Client:   hangingClient{},
		Findings: []EscalatedFinding{escalatedFor("finding-1", "a")},
		Config:   Config{Enabled: true, MaxPerScan: 10, MaxTokens: 1024, CallTimeout: 50 * time.Millisecond},
	}

	done := make(chan Outcome, 1)
	go func() { done <- RunAll(context.Background(), in) }()

	select {
	case out := <-done:
		if out.Degraded != 1 {
			t.Fatalf("Outcome = %+v, want Degraded=1", out)
		}
		rec := readRecord(t, in, "finding-1")
		if rec.NarrativeStatus != StatusAbsentModelError {
			t.Errorf("NarrativeStatus = %q, want %q", rec.NarrativeStatus, StatusAbsentModelError)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunAll did not return within 5s of a 50ms CallTimeout — the per-call deadline is not being enforced")
	}
}

// TestRunAll_EmptyFindings proves zero escalated findings is a clean no-op.
func TestRunAll_EmptyFindings(t *testing.T) {
	s := newTempStore(t)
	in := Input{Store: s, Client: &scriptedClient{}, Findings: nil, Config: okConfig()}
	out := RunAll(context.Background(), in)
	if out.Investigated != 0 || out.Degraded != 0 || out.Skipped != 0 || len(out.Errors) != 0 {
		t.Errorf("Outcome = %+v, want all-zero", out)
	}
}

// headSHA reads the store's current HEAD commit sha via `git rev-parse HEAD`
// — core/store exposes no public sha accessor, so this shells out directly
// against the store's own repo path (Store.Path()), mirroring how
// core/store's own tests verify commit behavior.
func headSHA(t *testing.T, s *store.Store) string {
	t.Helper()
	out, err := exec.Command("git", "-C", s.Path(), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestRunAll_SetupPanicGuard proves review finding 1: a panic in RunAll's OWN
// body (setup — the sort/slice-copy region BEFORE the per-finding loop,
// which processOne's own guard cannot reach) is caught by RunAll's top-level
// defer/recover and converted into the Outcome accumulated so far plus a
// warning, never propagating out of RunAll. Forced via the
// runAllPanicHookForTest seam (there is no naturally-reachable panic in
// today's setup code — the seam exists precisely so this defensive guard is
// provably exercised rather than merely inspected).
func TestRunAll_SetupPanicGuard(t *testing.T) {
	s := newTempStore(t)
	orig := runAllPanicHookForTest
	runAllPanicHookForTest = func() { panic("simulated RunAll setup panic") }
	defer func() { runAllPanicHookForTest = orig }()

	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.5,"narrative":"should never be reached — setup panics first"}`}
	in := Input{
		Store:    s,
		Client:   client,
		Findings: []EscalatedFinding{escalatedFor("finding-1", "a")},
		Config:   okConfig(),
	}

	var out Outcome
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RunAll panicked out of its own defer/recover: %v", r)
			}
		}()
		out = RunAll(context.Background(), in)
	}()

	if len(out.Errors) == 0 {
		t.Error("expected a non-empty Errors entry describing the setup panic")
	}
	if out.Investigated != 0 || out.Degraded != 0 || out.Skipped != 0 {
		t.Errorf("Outcome = %+v, want all-zero counts (the panic pre-empted the per-finding loop entirely)", out)
	}
	if client.calls != 0 {
		t.Errorf("client called %d times, want 0 (the loop never ran)", client.calls)
	}
	if data, err := s.ReadSnapshot(recordPath("finding-1")); err != nil || len(data) != 0 {
		t.Errorf("expected no record written when RunAll panics in setup, got data=%q err=%v", data, err)
	}
}

// TestRunAll_ExistingRecordReadError_SkipsWithoutBurningBudgetOrCreatedAt
// proves review finding 2: when readExistingRecord's own read of an ALREADY
// EXISTING record fails with a transient error (as opposed to the record
// being cleanly absent), processOne skips the finding for THIS scan
// entirely — zero narrate calls, the record on disk left byte-for-byte
// untouched. Burning a metered call and resetting CreatedAt just because a
// transient read hiccup made a good record LOOK absent would be worse than
// doing nothing; the next scan simply retries the read.
func TestRunAll_ExistingRecordReadError_SkipsWithoutBurningBudgetOrCreatedAt(t *testing.T) {
	s := newTempStore(t)
	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"first pass, before the read error."}`}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}

	first := RunAll(context.Background(), in)
	if first.Investigated != 1 {
		t.Fatalf("seed run Outcome = %+v, want Investigated=1", first)
	}
	firstRec := readRecord(t, in, "finding-1")

	restore := corruptHeadCommitObjectForTest(t, s)
	second := RunAll(context.Background(), in)
	restore()

	if second.Investigated != 0 {
		t.Errorf("second run Investigated = %d, want 0 (a read error must never proceed to a model call)", second.Investigated)
	}
	if second.Skipped != 0 {
		t.Errorf("second run Skipped = %d, want 0 (this is the read-error skip, not the ok-skip path — it is tallied as Degraded)", second.Skipped)
	}
	if second.Degraded != 1 {
		t.Errorf("second run Degraded = %d, want 1 (the read-error skip must be visible, not silent)", second.Degraded)
	}
	if len(second.Errors) == 0 {
		t.Error("expected a non-empty Errors entry describing the read error")
	}
	if client.calls != 1 {
		t.Errorf("client called %d times across two runs, want 1 (the read error must NOT burn a metered call)", client.calls)
	}

	secondRec := readRecord(t, in, "finding-1")
	if secondRec.CreatedAt != firstRec.CreatedAt || secondRec.UpdatedAt != firstRec.UpdatedAt || secondRec.Narrative != firstRec.Narrative {
		t.Errorf("record was overwritten despite the read error: first=%+v second=%+v", firstRec, secondRec)
	}
}

// TestRunAll_AssemblyPanicOnPreviouslyDegradedRecord proves review finding 3:
// a panic strictly BEFORE any model call was ever attempted (evidence
// assembly) (a) gets the honest StatusAbsentInternalError label, never
// StatusAbsentModelError — an assembly bug is not a model failure — and (b)
// preserves a KNOWN prior CreatedAt instead of resetting it to now(), when
// one exists: here, a previously-degraded record from an earlier run (the
// re-investigation/refresh path, not a brand-new record).
func TestRunAll_AssemblyPanicOnPreviouslyDegradedRecord(t *testing.T) {
	s := newTempStore(t)
	// Seed a previously-degraded record (invalid model output) so the SECOND
	// run below takes the refresh path (found==true, not ok) rather than the
	// brand-new-record path.
	seedClient := &scriptedClient{reply: "not json at all"}
	seedIn := Input{Store: s, Client: seedClient, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
	seedOut := RunAll(context.Background(), seedIn)
	if seedOut.Degraded != 1 {
		t.Fatalf("seed run Outcome = %+v, want Degraded=1", seedOut)
	}
	seedRec := readRecord(t, seedIn, "finding-1")
	if seedRec.NarrativeStatus != StatusAbsentInvalidOutput {
		t.Fatalf("seed record NarrativeStatus = %q, want %q", seedRec.NarrativeStatus, StatusAbsentInvalidOutput)
	}

	// Sleep past RFC3339's 1s resolution so a changed UpdatedAt is provably
	// new, not a coincidence of running fast.
	time.Sleep(1100 * time.Millisecond)

	orig := processOnePanicHookForTest
	processOnePanicHookForTest = func(findingID string) {
		if findingID == "finding-1" {
			panic("simulated assembly panic")
		}
	}
	defer func() { processOnePanicHookForTest = orig }()

	client := &scriptedClient{reply: `{"verdict":"benign","confidence":0.9,"narrative":"should never be reached — assembly panics first"}`}
	in := Input{Store: s, Client: client, Findings: []EscalatedFinding{escalatedFor("finding-1", "a")}, Config: okConfig()}
	out := RunAll(context.Background(), in)

	if out.Degraded != 1 || out.Investigated != 0 {
		t.Fatalf("Outcome = %+v, want Degraded=1/Investigated=0", out)
	}
	if client.calls != 0 {
		t.Errorf("client called %d times, want 0 (assembly panicked before any model call was attempted)", client.calls)
	}

	rec := readRecord(t, in, "finding-1")
	if rec.NarrativeStatus != StatusAbsentInternalError {
		t.Errorf("NarrativeStatus = %q, want %q (an assembly panic is inquest's OWN bug, never a model-error mislabel)", rec.NarrativeStatus, StatusAbsentInternalError)
	}
	if rec.CreatedAt != seedRec.CreatedAt {
		t.Errorf("CreatedAt = %q, want preserved from the prior record %q — a panic must not silently reset it", rec.CreatedAt, seedRec.CreatedAt)
	}
	if rec.UpdatedAt == seedRec.UpdatedAt {
		t.Error("UpdatedAt did not change — expected a fresh UpdatedAt on this refresh attempt")
	}
}
