package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{}

func makeSkillEvent(id, evType, actor string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    "app",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 11, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_BenignSkill(t *testing.T) {
	ev := makeSkillEvent("evt-a", "skill_install", "alice", map[string]interface{}{
		"name":        "code-reviewer",
		"description": "reviews pull requests",
		"url":         "https://skills.internal.acme.com/code-reviewer",
		"permissions": []string{"read:pull_requests"},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for benign skill, got %d: %+v", len(findings), findings)
	}
}

func TestEvaluate_NonSkillEvent(t *testing.T) {
	ev := event.Event{
		ID: "evt-b", Source: "app", Type: "login", Actor: "alice",
		Timestamp: time.Date(2026, 4, 10, 11, 0, 0, 0, time.UTC),
	}
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-skill event, got %d", len(findings))
	}
}

func TestEvaluate_NgrokURL(t *testing.T) {
	ev := makeSkillEvent("evt-c", "skill_install", "attacker", map[string]interface{}{
		"name": "data-helper",
		"url":  "https://abc123.ngrok.io/exfil",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for ngrok URL, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_WebhookSiteURL(t *testing.T) {
	ev := makeSkillEvent("evt-d", "skill_register", "attacker", map[string]interface{}{
		"name":   "data-sync",
		"source": "https://webhook.site/abc123",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for webhook.site URL, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_IPAddressURL(t *testing.T) {
	ev := makeSkillEvent("evt-e", "skill_install", "attacker", map[string]interface{}{
		"name": "updater",
		"url":  "http://192.168.1.100:8080/payload",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for IP address URL, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_ExcessivePermissions_Star(t *testing.T) {
	ev := makeSkillEvent("evt-f", "skill_install", "alice", map[string]interface{}{
		"name":        "admin-tool",
		"permissions": []string{"*"},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard permission, got 0")
	}
	assertSeverity(t, findings[0], "high")
}

func TestEvaluate_ExcessivePermissions_Admin(t *testing.T) {
	ev := makeSkillEvent("evt-g", "skill_update", "alice", map[string]interface{}{
		"name":        "org-tool",
		"permissions": []string{"read:issues", "admin:*"},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for admin:* permission, got 0")
	}
}

func TestEvaluate_SuspiciousKeyword_Backdoor(t *testing.T) {
	ev := makeSkillEvent("evt-h", "skill_install", "attacker", map[string]interface{}{
		"name":        "helper-backdoor",
		"description": "assists with tasks",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for 'backdoor' keyword, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_SuspiciousKeyword_ReverseShell(t *testing.T) {
	ev := makeSkillEvent("evt-i", "skill_register", "attacker", map[string]interface{}{
		"name":        "network-util",
		"description": "provides reverse shell capability for debugging",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for 'reverse shell' keyword, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_EncodedBinaryPayload(t *testing.T) {
	// Craft a base64 payload with >20% non-printable bytes (simulates binary/ELF).
	binary := make([]byte, 80)
	for i := range binary {
		if i%4 == 0 {
			binary[i] = 0x00 // null bytes — definitely non-printable
		} else {
			binary[i] = byte('A' + i%26)
		}
	}
	encoded := base64.StdEncoding.EncodeToString(binary)
	ev := makeSkillEvent("evt-j", "skill_install", "attacker", map[string]interface{}{
		"name":   "loader",
		"config": map[string]string{"blob": encoded},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for binary encoded payload, got 0")
	}
}

func TestEvaluate_RawGithubScriptURL(t *testing.T) {
	ev := makeSkillEvent("evt-k", "skill_install", "attacker", map[string]interface{}{
		"name": "setup-tool",
		"url":  "https://raw.githubusercontent.com/evil/repo/main/install.sh",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for raw GitHub script URL, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func TestEvaluate_BurpCollaborator(t *testing.T) {
	ev := makeSkillEvent("evt-l", "skill_install", "pentester", map[string]interface{}{
		"name": "probe",
		"url":  "https://abc.burpcollaborator.net/callback",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for Burp Collaborator URL, got 0")
	}
	assertSeverity(t, findings[0], "critical")
}

func assertSeverity(t *testing.T, f finding.Finding, want string) {
	t.Helper()
	if f.Severity != want {
		t.Errorf("severity: got %q want %q (finding: %+v)", f.Severity, want, f)
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
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		got = append(got, evaluate(ev, bl)...)
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
