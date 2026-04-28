package quality_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestMallcopAutomatonChartParses loads charts/mallcop-automaton.toml.tmpl,
// substitutes all {{PLACEHOLDER}} vars with test values, parses it as TOML,
// and verifies the required structure: identity present, worksource campfire-bound,
// and party_grant for mallcop:operator present. This is the F3A chart contract test.
func TestMallcopAutomatonChartParses(t *testing.T) {
	root := repoRoot(t)
	chartPath := filepath.Join(root, "charts", "mallcop-automaton.toml.tmpl")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — create charts/mallcop-automaton.toml.tmpl (F3A)", chartPath, err)
	}

	// Substitute all template placeholders with test values.
	content := string(data)
	replacements := map[string]string{
		"{{OPERATOR_CAMPFIRE_ID}}": "test-campfire-abc123",
		"{{MODEL_STRONG}}":         "claude-opus-4-5",
		"{{INSTANCE}}":             "test",
		"{{TOOL_BIN_DIR}}":         "/usr/local/bin",
		"{{FIXTURE_DIR}}":          "/tmp/fixtures",
		"{{FORGE_API_URL}}":        "https://forge.example.com",
		"{{FORGE_API_KEY}}":        "test-key-abc",
		"{{RUN_ID}}":               "test-run",
	}
	for placeholder, value := range replacements {
		content = strings.ReplaceAll(content, placeholder, value)
	}

	// Parse as TOML — this is the primary assertion: no parse error.
	var chart map[string]interface{}
	if _, err := toml.Decode(content, &chart); err != nil {
		t.Fatalf("charts/mallcop-automaton.toml.tmpl TOML parse error: %v\n\n(Substituted content preview: %.500s)", err, content)
	}

	// Assert [identity] block is present with required fields.
	identity, ok := chart["identity"].(map[string]interface{})
	if !ok {
		t.Error("charts/mallcop-automaton.toml.tmpl: missing [identity] block")
	} else {
		if _, ok := identity["name"]; !ok {
			t.Error("charts/mallcop-automaton.toml.tmpl: [identity] missing 'name'")
		}
		if _, ok := identity["key_file"]; !ok {
			t.Error("charts/mallcop-automaton.toml.tmpl: [identity] missing 'key_file'")
		}
	}

	// Assert [[worksources]] is present and campfire-bound.
	worksources, ok := chart["worksources"].([]map[string]interface{})
	if !ok || len(worksources) == 0 {
		t.Error("charts/mallcop-automaton.toml.tmpl: missing [[worksources]] block")
	} else {
		ws := worksources[0]
		if campfire, ok := ws["campfire"].(string); !ok || campfire == "" {
			t.Error("charts/mallcop-automaton.toml.tmpl: worksource missing 'campfire' (must be campfire-bound, not ready-queue)")
		}
		// Verify mallcop:operator skill is declared.
		skills, _ := ws["skills"].([]interface{})
		hasOperator := false
		for _, s := range skills {
			if sv, ok := s.(string); ok && sv == "mallcop:operator" {
				hasOperator = true
				break
			}
		}
		if !hasOperator {
			t.Error("charts/mallcop-automaton.toml.tmpl: worksource skills must include 'mallcop:operator'")
		}
	}

	// Assert [tools.party_grants] includes mallcop:operator entry.
	toolsBlock, hasTools := chart["tools"].(map[string]interface{})
	if !hasTools {
		t.Error("charts/mallcop-automaton.toml.tmpl: missing [tools] block")
	} else {
		partyGrants, ok := toolsBlock["party_grants"].(map[string]interface{})
		if !ok {
			t.Error("charts/mallcop-automaton.toml.tmpl: missing [tools.party_grants]")
		} else {
			if _, ok := partyGrants["mallcop:operator"]; !ok {
				t.Error("charts/mallcop-automaton.toml.tmpl: [tools.party_grants] missing 'mallcop:operator' entry")
			}
		}
	}

	// Assert [lifecycle] max_workers = 1 (single operator agent, serialized for human interaction).
	lifecycle, hasLifecycle := chart["lifecycle"].(map[string]interface{})
	if !hasLifecycle {
		t.Error("charts/mallcop-automaton.toml.tmpl: missing [lifecycle] block")
	} else {
		maxWorkers, _ := lifecycle["max_workers"].(int64)
		if maxWorkers != 1 {
			t.Errorf("charts/mallcop-automaton.toml.tmpl: [lifecycle].max_workers = %d, want 1 (single operator agent)", maxWorkers)
		}
	}

	// Assert all 4 new F3A operator tool names appear in the chart.
	newTools := []string{"list-findings", "read-events", "read-recent-chat", "search-chat-history"}
	for _, toolName := range newTools {
		if !strings.Contains(content, toolName) {
			t.Errorf("charts/mallcop-automaton.toml.tmpl: missing tool %q — F3A operator tools must be declared in the chart", toolName)
		}
	}
}
