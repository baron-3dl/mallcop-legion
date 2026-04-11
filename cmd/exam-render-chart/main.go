// cmd/exam-render-chart renders charts/exam.toml.tmpl into a ready-to-boot
// legion chart for a specific exam run.
//
// Usage:
//
//	exam-render-chart --template charts/exam.toml.tmpl \
//	                  --run R1 \
//	                  --out .run/exam-R1/chart.toml \
//	                  [--forge-url http://localhost:4000]
//
// What it does:
//  1. Reads the template file.
//  2. Replaces {{RUN_ID}} with --run and {{FORGE_API_URL}} with --forge-url.
//  3. Creates .run/exam-<run>/ directory.
//  4. Generates a fresh ed25519 keypair and writes the private key as JSON
//     to .run/exam-<run>/identity.json (format: {"private_key":"<hex>"}).
//  5. Writes the rendered chart to --out.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "exam-render-chart: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	tmplPath := flag.String("template", "", "path to .toml.tmpl file (required)")
	runID := flag.String("run", "", "run identifier, e.g. R1 (required)")
	outPath := flag.String("out", "", "output chart path (required)")
	forgeURL := flag.String("forge-url", "", "Forge API URL injected into {{FORGE_API_URL}} (optional)")
	flag.Parse()

	if *tmplPath == "" {
		return fmt.Errorf("--template is required")
	}
	if *runID == "" {
		return fmt.Errorf("--run is required")
	}
	if *outPath == "" {
		return fmt.Errorf("--out is required")
	}

	rendered, err := renderTemplate(*tmplPath, *runID, *forgeURL)
	if err != nil {
		return fmt.Errorf("rendering template: %w", err)
	}

	runDir := filepath.Join(".run", "exam-"+*runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("creating run dir %s: %w", runDir, err)
	}

	if err := writeIdentity(runDir); err != nil {
		return fmt.Errorf("writing identity: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	if err := os.WriteFile(*outPath, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("writing chart to %s: %w", *outPath, err)
	}

	fmt.Printf("chart written to %s\n", *outPath)
	fmt.Printf("identity written to %s\n", filepath.Join(runDir, "identity.json"))
	return nil
}

// renderTemplate reads tmplPath and substitutes {{RUN_ID}} and {{FORGE_API_URL}}.
func renderTemplate(tmplPath, runID, forgeURL string) (string, error) {
	data, err := os.ReadFile(tmplPath)
	if err != nil {
		return "", fmt.Errorf("reading template %s: %w", tmplPath, err)
	}
	out := strings.ReplaceAll(string(data), "{{RUN_ID}}", runID)
	out = strings.ReplaceAll(out, "{{FORGE_API_URL}}", forgeURL)
	return out, nil
}

// identityFile is the JSON structure written for the legion identity.
// The private key is hex-encoded (lowercase) per legion's ed25519 identity format.
type identityFile struct {
	PrivateKey string `json:"private_key"`
}

// writeIdentity generates a fresh ed25519 keypair and writes identity.json
// under runDir.
func writeIdentity(runDir string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ed25519 key: %w", err)
	}

	payload := identityFile{
		PrivateKey: hex.EncodeToString(priv),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling identity: %w", err)
	}

	identityPath := filepath.Join(runDir, "identity.json")
	if err := os.WriteFile(identityPath, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", identityPath, err)
	}
	return nil
}
