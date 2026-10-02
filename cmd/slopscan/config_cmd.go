package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/Caseymccallum/slopscan/internal/config"
	"github.com/Caseymccallum/slopscan/internal/probe"
	"github.com/Caseymccallum/slopscan/internal/registry"
	"github.com/Caseymccallum/slopscan/internal/report"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

// configCommand reads the client configuration the agent actually loads and reports on every
// server named in it - the input format everyone uses and most scanners misread.
//
// With --probe each stdio entry is also started (with the env the config declares), asked for its
// tool list, and put through the same pipeline a file scan runs: classification, injection
// scanning, catalogue, drift. The config file is the deployment; this makes the scan match it.
func configCommand(dbPath, format *string) *cobra.Command {
	var probeThem bool
	var checkNames bool
	var npmRegistry, pypiRegistry string

	command := &cobra.Command{
		Use:   "config <mcp-config.json>",
		Short: "Check a client configuration (Claude Desktop, Cursor, VS Code) before it launches",
		Long: "Reads the mcpServers or servers block of a client configuration and checks what " +
			"each entry launches: downloads piped to shells, unpinned packages, filesystem mounts " +
			"that hand over everything, plaintext secrets in env, plain-HTTP endpoints. " +
			"Transport rules never fire on a stdio entry - a local process has no transport to " +
			"fail - and each report says what was evaluated and what was not.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sarifInputs := []report.SARIFInput{}
			breaking := false
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			entries, err := config.Load(args[0], raw)
			if err != nil {
				return err
			}

			reports := make([]config.EntryReport, 0, len(entries))
			npm := registry.Checker{Base: npmRegistry}
			pypi := registry.Checker{Base: pypiRegistry, Suffix: "/json"}
			for _, entry := range entries {
				findings := config.Check(entry)
				if checkNames {
					// The slopsquat check at the moment it matters: what this config is
					// about to install, looked up before anything installs it.
					findings = append(findings, config.CheckNames(entry, npm, pypi)...)
				}
				reports = append(reports, config.EntryReport{
					Entry:    config.Redacted(entry),
					Findings: findings,
					Notes:    config.Notes(entry),
				})
			}

			if *format == "sarif" {
				// SARIF mode gathers everything into one document - config findings now,
				// probe findings added below - because a security platform wants one upload
				// per run, not one per entry.
				for _, entryReport := range reports {
					for _, finding := range entryReport.Findings {
						sarifInputs = append(sarifInputs, report.SARIFInput{
							RuleID:   finding.Kind,
							Level:    finding.Severity,
							Message:  finding.Quote,
							Artifact: args[0],
							Subject:  entryReport.Entry.Name,
							OWASP:    finding.OWASP,
						})
					}
				}
			} else if *format == "json" {
				encoded, err := json.Marshal(reports)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
			} else {
				writeConfigReports(cmd.OutOrStdout(), reports)
			}

			// The exit-code contract in the gate direction: like `names` refusing a name that
			// does not exist, a high-severity finding means do not launch this as written.
			high := 0
			for _, entryReport := range reports {
				for _, finding := range entryReport.Findings {
					if finding.Severity == "high" {
						high++
					}
				}
			}
			// A finding that gates still owes the pipeline its alerts: emit before refusing.
			if high > 0 && *format == "sarif" {
				if err := report.WriteSARIF(cmd.OutOrStdout(), version, sarifInputs); err != nil {
					return err
				}
			}
			if high > 0 {
				if probeThem {
					// Probing launches the entries - exactly what a finding says not to do.
					return fmt.Errorf("%d high-severity finding(s); refusing to probe a "+
						"configuration that should not launch as written", high)
				}
				return fmt.Errorf("%d high-severity finding(s) in the configuration", high)
			}

			if probeThem {
				for _, entry := range entries {
					tools, err := probeEntry(cmd.Context(), entry)
					if err != nil {
						return fmt.Errorf("probe %s: %w", entry.Name, err)
					}
					if tools == nil {
						continue // nothing to launch and no endpoint to ask
					}
					// One server per entry, under the name the config gives it - which is the
					// name the agent will call it by, and the name drift should remember.
					if *format == "sarif" {
						view, comparison, err := evaluate(*dbPath, entry.Name, args[0], tools)
						if err != nil {
							return err
						}
						sarifInputs = append(sarifInputs, report.SARIFInputsFromServer(args[0], view)...)
						if comparison != nil {
							sarifInputs = append(sarifInputs, report.SARIFInputsFromDrift(args[0], *comparison)...)
							if comparison.Breaking {
								breaking = true
							}
						}
						continue
					}
					if err := analyse(cmd, *dbPath, *format, entry.Name, args[0], tools); err != nil {
						return err
					}
				}
			}

			if *format == "sarif" {
				if err := report.WriteSARIF(cmd.OutOrStdout(), version, sarifInputs); err != nil {
					return err
				}
				if breaking {
					return &BreakingError{Message: "breaking changes against the pinned baseline"}
				}
			}
			return nil
		},
	}

	command.Flags().BoolVar(&probeThem, "probe", false,
		"also ask every entry for its tool list (stdio servers started, remote endpoints contacted), "+
			"then scan, record, and compare with the pinned baseline")
	command.Flags().BoolVar(&checkNames, "check-names", false,
		"look up every package the launch lines fetch, and flag names no registry knows (network)")
	command.Flags().StringVar(&npmRegistry, "registry", "https://registry.npmjs.org",
		"npm package-info endpoint for --check-names")
	command.Flags().StringVar(&pypiRegistry, "pypi-registry", "https://pypi.org/pypi",
		"PyPI package-info endpoint for --check-names")
	return command
}

// probeEntry asks one config entry for its tools the way the agent would launch or reach it: a
// stdio server is started with the env the config declares, a remote endpoint is asked over its
// transport with its headers. nil means the entry has neither a command nor a URL to ask.
func probeEntry(ctx context.Context, entry config.Entry) ([]risk.Tool, error) {
	switch {
	case entry.Type == "stdio":
		return probe.ToolsIn(ctx, entry.Env, entry.Command, entry.Args...)
	case entry.URL != "":
		return probe.ToolsURL(ctx, entry.URL, entry.Headers)
	default:
		return nil, nil
	}
}

// writeConfigReports prints each entry's findings and scoping notes, worst entries first.
func writeConfigReports(w io.Writer, reports []config.EntryReport) {
	for _, report := range reports {
		findings := len(report.Findings)
		if findings == 0 {
			fmt.Fprintf(w, "%-24s %s: clean\n", report.Entry.Name, report.Entry.Type)
		} else {
			fmt.Fprintf(w, "%-24s %s: %d finding(s)\n", report.Entry.Name, report.Entry.Type, findings)
		}
		for _, finding := range report.Findings {
			fmt.Fprintf(w, "    ! %s %s/%s: %s\n", finding.OWASP, finding.Severity, finding.Kind, finding.Quote)
		}
		for _, note := range report.Notes {
			fmt.Fprintf(w, "    - %s\n", note)
		}
	}
}