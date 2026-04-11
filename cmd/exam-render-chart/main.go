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
//  4. Generates a fresh ed25519 keypair and writes identity.json to
//     .run/exam-<run>/identity.json using campfire identity.Generate()+Save().
//     The file format is compatible with campfire identity.Load() and legion's
//     loadIdentity helper: base64-encoded public_key, private_key, version=1,
//     and created_at timestamp.
//  5. Writes the rendered chart to --out.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/campfire-net/campfire/pkg/identity"
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

// writeIdentity generates a fresh ed25519 keypair and writes identity.json
// under runDir using the campfire identity package. The resulting file is
// compatible with campfire identity.Load() (which legion's loadIdentity calls).
//
// The file contains: version=1, public_key (base64), private_key (base64),
// created_at (Unix nanoseconds). The hex-encoded format previously used was
// incompatible — Go JSON decodes []byte as base64, so loading a hex string
// into ed25519.PrivateKey yielded 96 bytes, failing the 64-byte size check.
func writeIdentity(runDir string) error {
	id, err := identity.Generate()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	identityPath := filepath.Join(runDir, "identity.json")
	if err := id.Save(identityPath); err != nil {
		return fmt.Errorf("saving identity to %s: %w", identityPath, err)
	}
	return nil
}
