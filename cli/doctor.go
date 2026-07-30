package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
)

// doctor.go implements `mallcop doctor <connector-id>` — the operator-facing
// entry point onto the GrantClaim self-diagnosis kernel (design
// docs/design/onboarding-self-service.md §3/§6; core/connect/diagnose.go).
//
// It is presentation and orchestration ONLY (this item's HARD CONSTRAINT,
// R4 dual-audience): every byte of diagnosis logic — what a failure means,
// how a fix is ranked, whether a command is stale — lives in the connector's
// own Diagnose/Remediate (core/connect.Diagnosable, driven here across the
// process boundary by connect/exec.ExecConnector for a real cloud sibling).
// This file's job is to find the right connector, call Diagnose, print what
// comes back, and persist it through the SAME kernel functions
// `mallcop scan`'s pipeline already calls on a connect failure
// (core/pipeline/grantwiring.go's RecordDiagnosis/RecordConfirmOutcome) — the
// eventual chat/MCP skin (mallcoppro-99b0) calls those exact same functions,
// never a reimplementation.
//
// Usage:
//
//	mallcop doctor <connector-id> [--config <mallcop.yaml>] [--store <dir>] [--json]
//	mallcop doctor <connector-id> --confirm <grant-ref> [--config <mallcop.yaml>] [--store <dir>] [--json]
//
// The first form runs Diagnose and records a GRANT-MISS/status row (grant_ref
// in the output). After the operator applies one of the printed
// RemediationOptions by hand, the second form re-probes (Confirm) and records
// the outcome — a resolution row when the fix worked, a fresh miss when it
// didn't (core/pipeline's NEW-A19 semantics) — against the ORIGINAL row's
// grant_ref, through the real git-backed store.
//
// Exit codes: 0 healthy/resolved, 1 (errFindings) deficient/still-failing —
// same sentinel `mallcop scan`/`mallcop status --gate` use for "something
// needs an operator's attention" — 2 any other command failure.
func runDoctor(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("doctor: usage: mallcop doctor <connector-id> [--config <mallcop.yaml>] [--store <dir>] [--json] [--confirm <grant-ref>]")
	}
	connectorID := args[0]

	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides discovery/$"+config.EnvConfigPath+")")
	storePath := fs.String("store", "", "Path to the git-repo store where grant diagnoses are recorded (overrides config store.path)")
	asJSON := fs.Bool("json", false, "Emit the structured DiagnosisReport as JSON (the same shape the chat/MCP skin consumes) instead of the human-readable form")
	confirmRef := fs.String("confirm", "", "Re-probe <connector-id> after applying a remediation and record the outcome against a PRIOR run's grant_ref")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	cfg, cfgPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("doctor: %w", err)
	}
	haveConfig := cfgPath != ""
	if !haveConfig || len(cfg.Connectors) == 0 {
		return fmt.Errorf("doctor: no connectors configured (a mallcop.yaml with a connectors: list is required to name one to diagnose)")
	}

	resolvedStore := *storePath
	if resolvedStore == "" {
		resolvedStore = cfg.Store.Path
	}
	if resolvedStore == "" {
		return fmt.Errorf("doctor: --store is required (the git-repo path where grant diagnoses are recorded)")
	}

	st, err := openOrInitStore(resolvedStore)
	if err != nil {
		return err
	}

	// buildConnectors (cli/scan.go) is the SAME config -> connector composition
	// root `mallcop scan` uses — reusing it, rather than hand-rolling a second
	// connector-construction path here, is what guarantees `mallcop doctor` is
	// diagnosing the exact connector `mallcop scan` would pull from. No
	// learned-mapping overlay is needed for diagnosis (a nil *overlay.Overlay is
	// a valid empty overlay).
	conn, err := buildConnectors(cfg, resolvedStore, nil)
	if err != nil {
		return fmt.Errorf("doctor: %w", err)
	}

	diag, err := findDiagnosable(conn, connectorID)
	if err != nil {
		return fmt.Errorf("doctor: %w", err)
	}

	ctx := context.Background()

	if *confirmRef != "" {
		return runDoctorConfirm(ctx, st, diag, connectorID, *confirmRef, *asJSON)
	}
	return runDoctorDiagnose(ctx, st, diag, *asJSON)
}

// findDiagnosable locates the connect.Diagnosable named connectorID among
// every diagnosable reachable from conn, via pipeline.Diagnosables — the
// EXACT SAME kernel walk core/pipeline's recordConnectorDiagnosis and
// confirmResolvedGrants already use to reach past a production
// *connect.MultiConnector (cli/scan.go's buildConnectors ALWAYS returns one,
// even for a single configured source) into its real leaf connectors. This
// function does not re-derive that walk; it only picks, by ID, among what
// pipeline.Diagnosables already found — the "presentation and orchestration
// only" this item's HARD CONSTRAINT requires.
func findDiagnosable(conn connect.Connector, connectorID string) (connect.Diagnosable, error) {
	diags := pipeline.Diagnosables(conn)

	for _, d := range diags {
		if d.ID() == connectorID {
			return d, nil
		}
	}

	var known []string
	for _, d := range diags {
		known = append(known, d.ID())
	}
	if len(known) == 0 {
		return nil, fmt.Errorf("connector %q not found: no configured connector supports self-diagnosis", connectorID)
	}
	return nil, fmt.Errorf("connector %q not found among the connectors that support self-diagnosis: %v", connectorID, known)
}

// doctorReport is the --json payload `mallcop doctor` prints: the kernel's
// own connect.DiagnosisReport embedded verbatim (so every DiagnosisReport
// field appears at the top level of the JSON exactly as the wire contract
// connect/exec.ExecConnector.Diagnose parses defines it — mallcoppro-99b0's
// chat/MCP skin consumes this SAME shape) plus GrantRef: the grants-stream
// commit SHA Store.Append returned for the row this call just wrote, so a
// caller (operator or chat) can carry it forward into a later --confirm
// call without a separate store query.
type doctorReport struct {
	connect.DiagnosisReport
	GrantRef string `json:"grant_ref,omitempty"`
}

// runDoctorDiagnose is the first form: Diagnose, print, record.
func runDoctorDiagnose(ctx context.Context, st *store.Store, diag connect.Diagnosable, asJSON bool) error {
	report, err := diag.Diagnose(ctx)
	if err != nil {
		return fmt.Errorf("diagnose %q: %w", diag.ID(), err)
	}

	sha, err := pipeline.RecordDiagnosis(st, report)
	if err != nil {
		return err
	}

	if asJSON {
		if err := printDoctorJSON(doctorReport{DiagnosisReport: report, GrantRef: sha}); err != nil {
			return err
		}
	} else {
		printDiagnosisReport(report, sha)
	}

	if diagnosisDeficient(report) {
		return errFindings
	}
	return nil
}

// runDoctorConfirm is the second form: re-probe (the kernel's Confirm
// re-probes by calling Diagnose again — the exact same pattern
// core/pipeline's confirmResolvedGrants already established for the
// automatic `mallcop scan` path), then record the outcome against missRef
// through pipeline.RecordConfirmOutcome — the IDENTICAL function that path
// calls.
func runDoctorConfirm(ctx context.Context, st *store.Store, diag connect.Diagnosable, connectorID, missRef string, asJSON bool) error {
	report, err := diag.Diagnose(ctx)
	if err != nil {
		return fmt.Errorf("confirm %q: re-probe: %w", connectorID, err)
	}

	result := connect.ConfirmResult{
		// Resolved mirrors core/pipeline's confirmResolvedGrants exactly:
		// Known:true closes the loop, Known:false means the applied fix did
		// not (yet) resolve the deficiency.
		Resolved:  report.Diagnosis.Known,
		Diagnosis: report.Diagnosis,
		CheckedAt: time.Now().UTC(),
	}

	// The RecordDiagnosis row this is confirming carries no Cloud/AccessMode
	// (connect.DiagnosisReport has no such fields to source them from —
	// core/pipeline.recordConnectorDiagnosis's own rows leave them empty too),
	// so the identity cross-check is against the same empty values.
	sha, _, err := pipeline.RecordConfirmOutcome(st, missRef, connectorID, "", "", result)
	if err != nil {
		return fmt.Errorf("confirm %q: %w", connectorID, err)
	}

	if asJSON {
		if err := printDoctorJSON(doctorConfirmReport{
			doctorReport: doctorReport{DiagnosisReport: report, GrantRef: sha},
			Resolved:     result.Resolved,
		}); err != nil {
			return err
		}
	} else {
		printConfirmResult(connectorID, result, sha)
	}

	if !result.Resolved {
		return errFindings
	}
	return nil
}

// doctorConfirmReport is the --json payload for the --confirm form: the same
// doctorReport shape plus Resolved — the ConfirmResult's own headline verdict,
// which has no place on a plain DiagnosisReport (that struct describes ONE
// probe, not a before/after comparison).
type doctorConfirmReport struct {
	doctorReport
	Resolved bool `json:"resolved"`
}

// diagnosisDeficient reports whether report describes a connector an operator
// still needs to act on: EITHER the diagnosis is unclassified (Known == false,
// a GRANT-MISS the corpus hasn't mapped) OR it is classified but has a ranked
// remediation to apply. A classified diagnosis with NO remediation is the
// kernel's own definition of healthy (core/connect/diagnose.go's Remediation
// doc: "Empty when Diagnosis.Known is false ... or the deficiency needs no
// remediation") — this reads that field, it does not re-derive it.
func diagnosisDeficient(report connect.DiagnosisReport) bool {
	return !report.Diagnosis.Known || len(report.Remediation) > 0
}

// printDoctorJSON writes v as indented JSON to stdout.
func printDoctorJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printDiagnosisReport writes the human-readable form: the connector's
// current status, then every RemediationOption ranked narrowest-first with
// its blast-radius line, dry-run preview, and KnownIssues (which is where a
// staleness banner lives, design §6 safety property 4 — this function prints
// KnownIssues verbatim and in order; it never inspects or special-cases their
// text, that would be diagnosis logic this file must not carry).
func printDiagnosisReport(report connect.DiagnosisReport, sha string) {
	id := report.ConnectorID
	if id == "" {
		id = "(unknown)"
	}
	fmt.Printf("Connector:  %s\n", id)
	if report.Diagnosis.Known {
		fmt.Printf("Diagnosis:  %s (confidence %.2f)\n", report.Diagnosis.Summary, report.Diagnosis.Confidence)
	} else {
		fmt.Printf("Diagnosis:  UNKNOWN (confidence %.2f) — %s\n", report.Diagnosis.Confidence, report.Diagnosis.Summary)
		fmt.Println("            mallcop could not classify this failure; a GRANT-MISS has been recorded for an operator to review.")
	}

	if len(report.Remediation) == 0 {
		if report.Diagnosis.Known {
			fmt.Println("Status:     HEALTHY — nothing to remediate")
		}
	} else {
		fmt.Printf("Remediation (%d option(s), narrowest-first):\n", len(report.Remediation))
		for i, opt := range report.Remediation {
			fmt.Printf("  [%d] %s\n", i+1, opt.Command)
			fmt.Printf("      Blast radius: %s\n", opt.BlastRadius)
			if opt.DryRun != nil {
				fmt.Printf("      Dry run:      %s\n", *opt.DryRun)
			}
			for _, note := range opt.KnownIssues {
				fmt.Printf("      Note:         %s\n", note)
			}
		}
	}

	fmt.Printf("Grant ref:  %s (pass to `mallcop doctor %s --confirm %s` after applying a fix)\n", sha, id, sha)
}

// printConfirmResult writes the human-readable form of a --confirm run.
func printConfirmResult(connectorID string, result connect.ConfirmResult, sha string) {
	if result.Resolved {
		fmt.Printf("Confirm:    RESOLVED — %s is now healthy (recorded at %s)\n", connectorID, sha)
		return
	}
	fmt.Printf("Confirm:    STILL DEFICIENT — %s\n", result.Diagnosis.Summary)
	fmt.Printf("Grant ref:  %s (a fresh miss; re-run --confirm %s after trying another fix)\n", sha, sha)
}
