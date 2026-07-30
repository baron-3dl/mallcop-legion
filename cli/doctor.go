package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
//	mallcop doctor --all [--config <mallcop.yaml>] [--store <dir>] [--json]
//
// The first form runs Diagnose and records a GRANT-MISS/status row (grant_ref
// in the output). After the operator applies one of the printed
// RemediationOptions by hand, the second form re-probes (Confirm) and records
// the outcome — a resolution row when the fix worked, a fresh miss when it
// didn't (core/pipeline's NEW-A19 semantics) — against the ORIGINAL row's
// grant_ref, through the real git-backed store.
//
// The third form, --all (mallcoppro-62c), is the aggregate the canonical
// scheduled-scan workflow (cli/deployrepo.go's scanWorkflowTemplate) drives:
// it diagnoses EVERY configured connector that supports self-diagnosis and
// prints the results as ONE array — see runDoctorAll's own doc for why that
// aggregation belongs here (one process, one Diagnosables walk) rather than
// a bash loop re-invoking the single-connector form above per connector.
//
// Exit codes: 0 healthy/resolved, 1 (errFindings) deficient/still-failing —
// same sentinel `mallcop scan`/`mallcop status --gate` use for "something
// needs an operator's attention" — 2 any other command failure.
func runDoctor(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("doctor: usage: mallcop doctor <connector-id>|--all [--config <mallcop.yaml>] [--store <dir>] [--json] [--confirm <grant-ref>]")
	}
	if args[0] == "--all" {
		return runDoctorAll(args[1:])
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

// runDoctorAll implements `mallcop doctor --all`: diagnoses EVERY configured
// connector that supports self-diagnosis and prints the results as ONE JSON
// array — the shape the canonical scheduled-scan workflow (cli/deployrepo.go's
// scanWorkflowTemplate "Publish doctor reports" step, mallcoppro-62c) writes
// verbatim to store/doctor.json on the findings branch for mallcop-pro's
// console (mallcoppro-99b0) to read.
//
// This is a SEPARATE invocation form from the single-connector
// `mallcop doctor <connector-id> --json` mallcoppro-529 shipped — that
// contract (one DiagnosisReport object per invocation, asserted by the
// mallcop-connectors sibling's own doctor_test.go) is UNCHANGED and
// untouched by this function. --all aggregates by walking the SAME
// pipeline.Diagnosables reachability findDiagnosable already uses, in one
// process, exactly the way `mallcop collect --json` already aggregates
// coverage gaps across every configured connector in one process rather
// than a caller looping a per-connector command — the established
// aggregation pattern in this codebase.
//
// A connector with no doctor support is silently absent from the array: it's
// never in pipeline.Diagnosables' walk to begin with (only connect/exec's
// ExecConnector — kind:cloud — implements Diagnosable today), so there is no
// separate "skip" branch to fall into — a scan must not die because one
// connector lacks a doctor, and here there is nothing that could die. A
// connector whose live Diagnose call DOES return an error (diagnoseAll,
// below) is likewise omitted from the array rather than represented with a
// synthetic/empty report — CRITICAL per the item's anti-lie contract: an
// operator reading doctor.json must be able to tell "this connector was
// never diagnosed" (absent from the array) apart from "this connector is
// healthy" (present, Known:true, no remediation). This function never
// fabricates the latter for the former.
//
// --all deliberately never calls pipeline.RecordDiagnosis: that writes an
// unconditional row to the grants stream on every call (core/pipeline's own
// doc on RecordDiagnosis), which is the right behavior for an operator
// explicitly running the single-connector form, or a genuine connect
// failure recording a GRANT-MISS — but would flood the grants stream with a
// steady-state row per configured connector on every scheduled run (hourly,
// per scanWorkflowTemplate's cron) regardless of health. doctor.json is a
// point-in-time observability snapshot for the console, not a driver of the
// interactive GrantClaim remediation loop.
func runDoctorAll(args []string) error {
	fs := flag.NewFlagSet("doctor --all", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides discovery/$"+config.EnvConfigPath+")")
	storePath := fs.String("store", "", "Path to the git-repo store (overrides config store.path) -- used only to construct connectors identically to the single-connector doctor/scan path; --all itself never writes to it")
	asJSON := fs.Bool("json", false, "Emit the aggregated []DiagnosisReport as a JSON array instead of the human-readable form")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, cfgPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("doctor --all: %w", err)
	}
	haveConfig := cfgPath != ""
	if !haveConfig || len(cfg.Connectors) == 0 {
		return fmt.Errorf("doctor --all: no connectors configured (a mallcop.yaml with a connectors: list is required)")
	}

	resolvedStore := *storePath
	if resolvedStore == "" {
		resolvedStore = cfg.Store.Path
	}

	// buildConnectors is the SAME config -> connector composition root
	// `mallcop scan` and the single-connector doctor form use (see
	// runDoctor's own comment) -- no second, hand-rolled construction path.
	conn, err := buildConnectors(cfg, resolvedStore, nil)
	if err != nil {
		return fmt.Errorf("doctor --all: %w", err)
	}

	diags := pipeline.Diagnosables(conn)

	reports, anyDeficient, anyError := diagnoseAll(context.Background(), diags, os.Stderr)

	if *asJSON {
		if err := printDoctorAllJSON(reports); err != nil {
			return err
		}
	} else {
		for _, report := range reports {
			printDoctorAllHuman(report)
		}
	}

	if anyDeficient || anyError {
		return errFindings
	}
	return nil
}

// diagnoseAll runs Diagnose (via ctx) against every d in diags and returns
// one connect.DiagnosisReport per connector whose call actually produced a
// report. A connector whose Diagnose call returns an error is OMITTED from
// reports -- never given a synthetic placeholder entry -- and a one-line
// warning is written to errW so the failure is reported honestly (e.g. the
// scheduled workflow's own step log) without aborting the loop or the
// caller's process: one connector's failed probe must never take down the
// aggregate for every other configured connector.
//
// anyDeficient is true when at least one PRESENT report is deficient
// (diagnosisDeficient); anyError is true when at least one Diagnose call was
// omitted this way. Both feed runDoctorAll's exit-code convention.
func diagnoseAll(ctx context.Context, diags []connect.Diagnosable, errW io.Writer) (reports []connect.DiagnosisReport, anyDeficient, anyError bool) {
	for _, d := range diags {
		report, err := d.Diagnose(ctx)
		if err != nil {
			fmt.Fprintf(errW, "doctor --all: diagnose %q: %v (omitted from doctor.json -- never diagnosed, never fabricated healthy)\n", d.ID(), err)
			anyError = true
			continue
		}
		reports = append(reports, report)
		if diagnosisDeficient(report) {
			anyDeficient = true
		}
	}
	return reports, anyDeficient, anyError
}

// printDoctorAllJSON writes reports as a JSON array to stdout -- an EMPTY
// array (never null) when nothing was diagnosed, so a reader (the console,
// or jq in the workflow step) always gets valid, well-typed JSON.
func printDoctorAllJSON(reports []connect.DiagnosisReport) error {
	if reports == nil {
		reports = []connect.DiagnosisReport{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// printDoctorAllHuman writes one summary line per report. It does not print a
// grant_ref/--confirm hint the way printDiagnosisReport does: --all never
// records to the grants stream, so there is no ref to hand back.
func printDoctorAllHuman(report connect.DiagnosisReport) {
	id := report.ConnectorID
	if id == "" {
		id = "(unknown)"
	}
	status := "HEALTHY"
	switch {
	case !report.Diagnosis.Known:
		status = "UNKNOWN"
	case len(report.Remediation) > 0:
		status = "DEFICIENT"
	}
	fmt.Printf("%-24s %-10s %s\n", id, status, report.Diagnosis.Summary)
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
