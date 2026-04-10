package main

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{}

func makeConfigEvent(id, evType, actor, source string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 16, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_BenignEvent(t *testing.T) {
	ev := makeConfigEvent("evt-a", "login", "alice", "aws", map[string]interface{}{})
	f := evaluate(ev, testBaseline)
	if f != nil {
		t.Fatalf("expected nil for non-config event, got %+v", f)
	}
}

func TestEvaluate_AuditLogDisabled(t *testing.T) {
	ev := makeConfigEvent("evt-b", "audit_log_disabled", "attacker", "aws", map[string]interface{}{})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for audit log disabled, got nil")
	}
	if f.Severity != "critical" {
		t.Errorf("severity: got %q want critical", f.Severity)
	}
	if f.Type != "config-drift" {
		t.Errorf("type: got %q want config-drift", f.Type)
	}
}

func TestEvaluate_CloudTrailStop(t *testing.T) {
	ev := makeConfigEvent("evt-c", "cloudtrail_stop", "attacker", "aws", map[string]interface{}{})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for cloudtrail stop, got nil")
	}
	if f.Severity != "critical" {
		t.Errorf("severity: got %q want critical", f.Severity)
	}
}

func TestEvaluate_MFADisabled(t *testing.T) {
	ev := makeConfigEvent("evt-d", "mfa_disabled", "admin", "okta", map[string]interface{}{
		"target_user": "carol",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for MFA disabled, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_SecurityGroupModify(t *testing.T) {
	ev := makeConfigEvent("evt-e", "security_group_modify", "alice", "aws", map[string]interface{}{
		"resource_name":      "sg-prod-web",
		"change_description": "added inbound rule 0.0.0.0/0:22",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for security group modify, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_IAMPolicyAttach(t *testing.T) {
	ev := makeConfigEvent("evt-f", "iam_policy_attach", "devops", "aws", map[string]interface{}{
		"policy_name": "AdministratorAccess",
		"target_user": "svc-new",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for IAM policy attach, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_IAMPolicyCreate(t *testing.T) {
	ev := makeConfigEvent("evt-g", "iam_policy_create", "devops", "aws", map[string]interface{}{
		"policy_name": "custom-s3-readonly",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for IAM policy create, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_ConfigChange(t *testing.T) {
	ev := makeConfigEvent("evt-h", "config_change", "alice", "github", map[string]interface{}{
		"config_key": "require_signed_commits",
		"old_value":  "true",
		"new_value":  "false",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for config change, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_LogBucketDelete(t *testing.T) {
	ev := makeConfigEvent("evt-i", "log_bucket_delete", "attacker", "aws", map[string]interface{}{
		"resource_name": "acme-cloudtrail-logs",
	})
	f := evaluate(ev, testBaseline)
	if f == nil {
		t.Fatal("expected finding for log bucket delete, got nil")
	}
	if f.Severity != "critical" {
		t.Errorf("severity: got %q want critical", f.Severity)
	}
}

func TestGoldenFixture(t *testing.T) {
	bl, err := baseline.Load("testdata/baseline.json")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	eventsFile, err := os.Open("testdata/events.jsonl")
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer eventsFile.Close()

	goldenFile, err := os.Open("testdata/findings.golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer goldenFile.Close()

	var got []finding.Finding
	scanner := bufio.NewScanner(eventsFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if f := evaluate(ev, bl); f != nil {
			got = append(got, *f)
		}
	}

	var want []finding.Finding
	gScanner := bufio.NewScanner(goldenFile)
	for gScanner.Scan() {
		line := gScanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("unmarshal golden finding: %v", err)
		}
		want = append(want, f)
	}

	if len(got) != len(want) {
		t.Fatalf("finding count: got %d want %d\ngot: %+v\nwant: %+v", len(got), len(want), got, want)
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID {
			t.Errorf("[%d] ID: got %q want %q", i, g.ID, w.ID)
		}
		if g.Severity != w.Severity {
			t.Errorf("[%d] Severity: got %q want %q", i, g.Severity, w.Severity)
		}
		if g.Type != w.Type {
			t.Errorf("[%d] Type: got %q want %q", i, g.Type, w.Type)
		}
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
