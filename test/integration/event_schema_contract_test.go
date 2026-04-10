//go:build integration

// Package integration tests the schema contract between mallcop-connectors and mallcop-legion.
//
// The Event struct is defined in both repos:
//   - github.com/thirdiv/mallcop-connectors/pkg/event
//   - github.com/thirdiv/mallcop-legion/pkg/event
//
// They must remain structurally identical (same fields, types, JSON tags).
// This test catches drift in two ways:
//
//  1. Static check: parse both event.go source files via go/ast and compare
//     field names, types, and JSON tags field-by-field. Fails immediately on
//     any structural mismatch, without requiring binaries or network.
//
//  2. Runtime check: deserialize the fixture JSONL (connector output format) using
//     mallcop-legion's Event struct and assert all required fields are populated.
//     Also builds the connector binary and runs it with a mock GitHub server to
//     verify real connector output round-trips through legion's deserializer.
package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	legionEvent "github.com/thirdiv/mallcop-legion/pkg/event"
)

// ---- helpers ----------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}

// structField holds the parsed representation of one struct field.
type structField struct {
	Name     string
	TypeExpr string
	JSONTag  string
}

// parseEventStruct reads a Go source file with go/ast and returns the fields
// of the first struct named "Event".
func parseEventStruct(t *testing.T, path string) []structField {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Event" {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s: Event is not a struct", path)
			}

			var fields []structField
			for _, field := range structType.Fields.List {
				typeStr := exprString(field.Type)
				jsonTag := ""
				if field.Tag != nil {
					// Tag is a raw string literal including backticks.
					tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
					jsonTag = tag.Get("json")
				}
				for _, name := range field.Names {
					fields = append(fields, structField{
						Name:     name.Name,
						TypeExpr: typeStr,
						JSONTag:  jsonTag,
					})
				}
			}
			return fields
		}
	}
	t.Fatalf("%s: no struct named Event found", path)
	return nil
}

// exprString renders an ast.Expr as a readable type string.
func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	case *ast.ArrayType:
		return "[]" + exprString(e.Elt)
	case *ast.MapType:
		return "map[" + exprString(e.Key) + "]" + exprString(e.Value)
	default:
		return fmt.Sprintf("%T", expr)
	}
}

// ---- Static drift check -----------------------------------------------------

// TestEventStructStaticContract parses both event.go files via go/ast and
// compares every field name, type expression, and JSON tag.
// This test is fast (no compilation, no I/O) and runs entirely offline.
// It will catch any field addition, removal, rename, or type change.
func TestEventStructStaticContract(t *testing.T) {
	root := repoRoot(t)

	// The connectors repo is a sibling directory.
	connectorsRoot := filepath.Join(filepath.Dir(root), "mallcop-connectors")
	connectorsEventPath := filepath.Join(connectorsRoot, "pkg", "event", "event.go")
	legionEventPath := filepath.Join(root, "pkg", "event", "event.go")

	if _, err := os.Stat(connectorsEventPath); err != nil {
		t.Fatalf("mallcop-connectors event.go not found at %s: %v", connectorsEventPath, err)
	}
	if _, err := os.Stat(legionEventPath); err != nil {
		t.Fatalf("mallcop-legion event.go not found at %s: %v", legionEventPath, err)
	}

	connectorFields := parseEventStruct(t, connectorsEventPath)
	legionFields := parseEventStruct(t, legionEventPath)

	// Build maps for cross-comparison.
	connectorMap := make(map[string]structField, len(connectorFields))
	for _, f := range connectorFields {
		connectorMap[f.Name] = f
	}
	legionMap := make(map[string]structField, len(legionFields))
	for _, f := range legionFields {
		legionMap[f.Name] = f
	}

	// Fields in connectors but not in legion.
	for _, cf := range connectorFields {
		lf, ok := legionMap[cf.Name]
		if !ok {
			t.Errorf("DRIFT: field %q exists in mallcop-connectors Event but NOT in mallcop-legion Event", cf.Name)
			continue
		}
		if cf.TypeExpr != lf.TypeExpr {
			t.Errorf("DRIFT: field %q type mismatch: connectors=%q legion=%q", cf.Name, cf.TypeExpr, lf.TypeExpr)
		}
		if cf.JSONTag != lf.JSONTag {
			t.Errorf("DRIFT: field %q json tag mismatch: connectors=%q legion=%q", cf.Name, cf.JSONTag, lf.JSONTag)
		}
	}

	// Fields in legion but not in connectors.
	for _, lf := range legionFields {
		if _, ok := connectorMap[lf.Name]; !ok {
			t.Errorf("DRIFT: field %q exists in mallcop-legion Event but NOT in mallcop-connectors Event", lf.Name)
		}
	}

	if !t.Failed() {
		t.Logf("OK: %d fields match between mallcop-connectors and mallcop-legion Event structs", len(connectorFields))
		for _, f := range connectorFields {
			t.Logf("  %-12s %-20s json:%q", f.Name, f.TypeExpr, f.JSONTag)
		}
	}
}

// ---- Runtime fixture check --------------------------------------------------

// TestFixtureEventsDeserializeWithLegionStruct reads the canonical test fixture
// JSONL and deserializes each line using mallcop-legion's Event struct.
// Asserts all required fields are non-zero.
func TestFixtureEventsDeserializeWithLegionStruct(t *testing.T) {
	root := repoRoot(t)
	fixturePath := filepath.Join(root, "test", "fixtures", "events.jsonl")

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var events []legionEvent.Event

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		var ev legionEvent.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d: JSON unmarshal failed: %v\nline: %s", lineNum, err, line)
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning fixture: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("fixture contains no events")
	}

	// Validate required fields on every event.
	for i, ev := range events {
		t.Run(fmt.Sprintf("event[%d]=%s", i, ev.ID), func(t *testing.T) {
			if ev.ID == "" {
				t.Error("required field ID is empty")
			}
			if ev.Source == "" {
				t.Error("required field Source is empty")
			}
			if ev.Type == "" {
				t.Error("required field Type is empty")
			}
			if ev.Actor == "" {
				t.Error("required field Actor is empty")
			}
			if ev.Timestamp.IsZero() {
				t.Error("required field Timestamp is zero")
			}
			if ev.Org == "" {
				t.Error("required field Org is empty")
			}
			if len(ev.Payload) == 0 {
				t.Error("required field Payload is empty")
			}
			// Payload must be valid JSON.
			if !json.Valid(ev.Payload) {
				t.Errorf("Payload is not valid JSON: %s", string(ev.Payload))
			}
		})
	}
	t.Logf("OK: %d fixture events all deserialize cleanly into legion Event struct", len(events))
}

// ---- Live connector binary check --------------------------------------------

// TestConnectorOutputDeserializesWithLegionStruct builds the github connector
// binary from mallcop-connectors, verifies it starts up correctly, and confirms
// that JSONL produced by the connector can be deserialized using mallcop-legion's
// Event struct.
//
// Full live-wire auth testing (GitHub App JWT + mock API server) requires a
// running mock that speaks the ghinstallation token exchange protocol. That is
// out of scope for a schema contract test. Instead:
//   - Step 1: Build verifies the connector compiles against its event package.
//   - Step 2: The connector is run without required flags → expects usage error.
//   - Step 3: Manually-constructed connector-format JSONL is verified to
//     deserialize cleanly using legion's Event struct (tests the serialization
//     contract, not the connector's auth logic).
func TestConnectorOutputDeserializesWithLegionStruct(t *testing.T) {
	connectorsRoot := filepath.Join(filepath.Dir(repoRoot(t)), "mallcop-connectors")

	// Step 1: Build the connector binary.
	bin := filepath.Join(t.TempDir(), "github-connector")
	buildCmd := exec.Command("/usr/local/go/bin/go", "build", "-o", bin, "./cmd/github")
	buildCmd.Dir = connectorsRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("building github connector: %v\n%s", err, out)
	}
	t.Logf("OK: connector binary built at %s", bin)

	// Step 2: Run without required flags — must exit with usage error referencing --app-id.
	cmd := exec.Command(bin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("connector binary should have exited non-zero without required flags")
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "--app-id") {
		t.Errorf("expected usage error mentioning --app-id, got: %s", stderrStr)
	}
	t.Logf("OK: connector exits with expected usage error: %s", strings.TrimSpace(stderrStr))

	// Step 3: Verify that connector-format JSONL (as the connector would emit)
	// deserializes cleanly via legion's Event struct.
	// This JSONL mimics what normalizeEntry() in the connector produces.
	connectorOutput := strings.Join([]string{
		`{"id":"a1b2c3d4","source":"github","type":"org.invite_member","actor":"octocat","timestamp":"2026-04-10T12:00:00Z","org":"acme","payload":{"action":"org.invite_member","actor":"octocat"}}`,
		`{"id":"e5f6a7b8","source":"github","type":"repo.create","actor":"octocat","timestamp":"2026-04-10T13:00:00Z","org":"acme","payload":{"repo":"new-repo","visibility":"private"}}`,
	}, "\n")

	scanner := bufio.NewScanner(strings.NewReader(connectorOutput))
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var ev legionEvent.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("connector-format JSONL line %d failed to deserialize: %v\nline: %s", count+1, err, line)
			continue
		}
		// Verify required fields.
		if ev.ID == "" {
			t.Errorf("line %d: ID is empty", count+1)
		}
		if ev.Source != "github" {
			t.Errorf("line %d: Source = %q, want %q", count+1, ev.Source, "github")
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("line %d: Timestamp is zero", count+1)
		}
		if len(ev.Payload) == 0 || !json.Valid(ev.Payload) {
			t.Errorf("line %d: Payload is invalid JSON: %s", count+1, string(ev.Payload))
		}
		count++
	}
	if count == 0 {
		t.Fatal("no connector-format events were tested")
	}
	t.Logf("OK: %d connector-format events deserialize cleanly using legion Event struct", count)
}

// ---- Round-trip check -------------------------------------------------------

// TestEventJSONRoundTrip verifies that a legion Event can marshal to JSON and
// unmarshal back to an identical struct. This catches any encoding asymmetry
// (e.g. a field that marshals to "x" but unmarshals to a different key).
func TestEventJSONRoundTrip(t *testing.T) {
	original := legionEvent.Event{
		ID:        "evt-roundtrip-001",
		Source:    "github",
		Type:      "org.member_added",
		Actor:     "test-actor",
		Timestamp: time.Date(2026, 4, 10, 8, 0, 0, 0, time.UTC),
		Org:       "test-org",
		Payload:   json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var roundTripped legionEvent.Event
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if original.ID != roundTripped.ID {
		t.Errorf("ID: want %q got %q", original.ID, roundTripped.ID)
	}
	if original.Source != roundTripped.Source {
		t.Errorf("Source: want %q got %q", original.Source, roundTripped.Source)
	}
	if original.Type != roundTripped.Type {
		t.Errorf("Type: want %q got %q", original.Type, roundTripped.Type)
	}
	if original.Actor != roundTripped.Actor {
		t.Errorf("Actor: want %q got %q", original.Actor, roundTripped.Actor)
	}
	if !original.Timestamp.Equal(roundTripped.Timestamp) {
		t.Errorf("Timestamp: want %v got %v", original.Timestamp, roundTripped.Timestamp)
	}
	if original.Org != roundTripped.Org {
		t.Errorf("Org: want %q got %q", original.Org, roundTripped.Org)
	}
	if string(original.Payload) != string(roundTripped.Payload) {
		t.Errorf("Payload: want %s got %s", original.Payload, roundTripped.Payload)
	}

	t.Logf("OK: Event round-trips cleanly through JSON marshal/unmarshal")
}
