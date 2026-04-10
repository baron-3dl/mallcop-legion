//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/BurntSushi/toml"
)

// chartRoot returns the absolute path to the mallcop-legion repo root.
func chartRoot(t *testing.T) string {
	t.Helper()
	// This file lives at test/integration/chart_validation_test.go.
	// Two directories up is the repo root.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// Chart is a minimal struct for parsing vertical-slice.toml.
// Only the fields we need to validate are declared.
type Chart struct {
	Identity struct {
		Name    string `toml:"name"`
		KeyFile string `toml:"key_file"`
	} `toml:"identity"`
	Worksources []struct {
		Type string `toml:"type"`
	} `toml:"worksources"`
	Budget struct {
		MaxTokensPerSession int64 `toml:"max_tokens_per_session"`
		MaxTokensPerTask    int64 `toml:"max_tokens_per_task"`
	} `toml:"budget"`
	Autonomy struct {
		MaxTasksPerSession int `toml:"max_tasks_per_session"`
		Escalation         struct {
			ScopeKeywords []string `toml:"scope_keywords"`
		} `toml:"escalation"`
	} `toml:"autonomy"`
	Capabilities struct {
		GatePolicy    string   `toml:"gate_policy"`
		Authority     string   `toml:"authority"`
		ToolAllowlist []string `toml:"tool_allowlist"`
		Seed          []struct {
			Name  string   `toml:"name"`
			Match []string `toml:"match"`
			Tools []string `toml:"tools"`
			Model string   `toml:"model"`
		} `toml:"seed"`
	} `toml:"capabilities"`
	Agents struct {
		Dir string `toml:"dir"`
	} `toml:"agents"`
	Lifecycle struct {
		MaxWorkers   int    `toml:"max_workers"`
		TimeLimit    string `toml:"time_limit"`
		PollInterval string `toml:"poll_interval"`
	} `toml:"lifecycle"`
	Campfire struct {
		TransportDir string `toml:"transport_dir"`
	} `toml:"campfire"`
	Inference struct {
		LocalModelMapping map[string]string `toml:"local_model_mapping"`
	} `toml:"inference"`
}

func TestChartParseable(t *testing.T) {
	root := chartRoot(t)
	chartPath := filepath.Join(root, "charts", "vertical-slice.toml")

	if _, err := os.Stat(chartPath); err != nil {
		t.Fatalf("chart file missing: %s: %v", chartPath, err)
	}

	var chart Chart
	if _, err := toml.DecodeFile(chartPath, &chart); err != nil {
		t.Fatalf("failed to parse chart: %v", err)
	}

	if chart.Identity.Name == "" {
		t.Error("identity.name is empty")
	}
	if chart.Identity.KeyFile == "" {
		t.Error("identity.key_file is empty")
	}
	if len(chart.Worksources) == 0 {
		t.Error("no [[worksources]] entries found")
	}
	for i, ws := range chart.Worksources {
		if ws.Type == "" {
			t.Errorf("worksources[%d].type is empty", i)
		}
	}
}

func TestChartRequiredPathsExist(t *testing.T) {
	root := chartRoot(t)

	paths := []struct {
		label string
		rel   string
	}{
		{"charts/vertical-slice.toml", "charts/vertical-slice.toml"},
		{"agents dir", "agents"},
		{"test/fixtures/baseline.json", "test/fixtures/baseline.json"},
		{"bin/we", "bin/we"},
	}

	for _, p := range paths {
		abs := filepath.Join(root, p.rel)
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("required path missing — %s: %s: %v", p.label, abs, err)
		}
	}
}

func TestChartAgentSpecsExist(t *testing.T) {
	root := chartRoot(t)
	agentsDir := filepath.Join(root, "agents")

	if _, err := os.Stat(agentsDir); err != nil {
		t.Fatalf("agents dir missing: %s: %v", agentsDir, err)
	}

	// triage agent spec must exist (referenced by capabilities.seed "triage")
	triageSpec := filepath.Join(agentsDir, "triage", "POST.md")
	if _, err := os.Stat(triageSpec); err != nil {
		t.Errorf("triage agent spec missing: %s: %v", triageSpec, err)
	}
}

func TestChartBinariesBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build test in short mode")
	}

	root := chartRoot(t)

	bins := []struct {
		label   string
		pkgPath string
	}{
		{"detector-unusual-login", "./cmd/detector-unusual-login/"},
		{"mallcop-finding-context", "./cmd/mallcop-finding-context/"},
	}

	for _, b := range bins {
		t.Run(b.label, func(t *testing.T) {
			cmd := exec.Command("go", "build", b.pkgPath)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("build failed for %s: %v\n%s", b.pkgPath, err, string(out))
			}
		})
	}
}
