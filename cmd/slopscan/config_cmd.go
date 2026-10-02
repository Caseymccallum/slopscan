package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/Caseymccallum/slopscan/internal/config"
	"github.com/Caseymccallum/slopscan/internal/probe"
)

// configCommand reads the client configuration the agent actually loads and reports on every
// server named in it - the input format everyone uses and most scanners misread.
//
// With --probe each stdio entry is also started (with the env the config declares), asked for its
// tool list, and put through the same pipeline a file scan runs: classification, injection
// scanning, catalogue, drift. The config file is the deployment; this makes the scan match it.
func configCommand(dbPath, format *string) *cobra.Command {
	var probeThem bool

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
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			entries, err := config.Load(args[0], raw)
			if err != nil {
				return err
			}

			reports := make([]config.EntryReport, 0, len(entries))
			for _, entry := range entries {
				reports = append(reports, config.EntryReport{
					Entry:    config.Redacted(entry),
					Findings: config.Check(entry),
					Notes:    config.Notes(entry),
				})
			}

			if *format == "json" {
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
			for _, report := range reports {
				for _, finding := range report.Findings {
					if finding.Severity == "high" {
						high++
					}
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
					if entry.Type != "stdio" {
						continue
					}
					tools, err := probe.ToolsIn(cmd.Context(), entry.Env, entry.Command, entry.Args...)
					if err != nil {
						return fmt.Errorf("probe %s: %w", entry.Name, err)
					}
					// One server per entry, under the name the config gives it - which is the
					// name the agent will call it by, and the name drift should remember.
					if err := analyse(cmd, *dbPath, *format, entry.Name, args[0], tools); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}

	command.Flags().BoolVar(&probeThem, "probe", false,
		"also start each stdio server, scan its tools, and compare with the pinned baseline")
	return command
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