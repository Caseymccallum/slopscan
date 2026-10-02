// Command slopscan is a local scanner for MCP server risk.
//
// It reads a server's tool list, classifies what each tool can do, scans the metadata for prompt
// injection, checks package names against a registry before anything installs them, and keeps
// every verdict in a local SQLite catalogue. Nothing here phones home: the catalogue is the point,
// and it belongs to whoever runs the scan.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Caseymccallum/slopscan/internal/catalogue"
	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/probe"
	"github.com/Caseymccallum/slopscan/internal/registry"
	"github.com/Caseymccallum/slopscan/internal/report"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

const version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:   "slopscan",
		Short: "Local scanner for MCP server risk: classification, prompt injection, and a private catalogue",
		Long: "slopscan reads MCP tool lists and says what each tool can do, what its metadata is trying " +
			"to tell the model, and whether a package name exists before anything installs it. Every " +
			"verdict is stored in a local database and printed with its evidence. Nothing phones home.",
		// A refused name or an unreadable file is the command working, not the user misusing it:
		// the error line is the message; the usage dump under it is noise.
		SilenceUsage: true,
	}

	var dbPath string
	root.PersistentFlags().StringVar(&dbPath, "db", "slopscan.db", "path to the local catalogue")

	root.AddCommand(scanCommand(&dbPath), probeCommand(&dbPath), dbCommand(&dbPath), namesCommand(), versionCommand())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// scanCommand reads a tool list (a JSON file of tools, as `tools/list` returns) and reports.
func scanCommand(dbPath *string) *cobra.Command {
	var source string
	var serverID string

	command := &cobra.Command{
		Use:   "scan <tools.json>",
		Short: "Classify a server's tools, scan its metadata, and record the verdict locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}

			var payload struct {
				Tools []risk.Tool `json:"tools"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				return fmt.Errorf("%s is not a tools list (%v)", args[0], err)
			}

			return analyse(cmd, *dbPath, serverID, source, payload.Tools)
		},
	}

	command.Flags().StringVar(&source, "source", "tools.json", "where these tools came from")
	command.Flags().StringVar(&serverID, "id", "local", "the server's identity in the catalogue")
	return command
}

// analyse is the pipeline both scan and probe run: classify every tool, scan every description,
// record the verdict, print the report. One implementation, so a probe and a file scan cannot
// drift apart into two different notions of what was found.
func analyse(cmd *cobra.Command, dbPath, serverID, source string, tools []risk.Tool) error {
	assessments := make([]risk.Assessment, 0, len(tools))
	findings := map[string][]injection.Finding{}
	for _, tool := range tools {
		assessments = append(assessments, risk.Classify(tool))
		if found := injection.Scan(tool.Name, tool.Description); len(found) > 0 {
			findings[tool.Name] = found
		}
	}

	cat, err := catalogue.Open(dbPath)
	if err != nil {
		return err
	}
	defer cat.Close()
	if err := cat.Record(serverID, source, assessments, findings); err != nil {
		return err
	}

	return report.Write(cmd.OutOrStdout(), report.Server{
		ID: serverID, Source: source, Tools: assessments, Findings: findings,
	})
}

// probeCommand asks a live MCP server for its tool list and reports on it.
//
// The server is started by slopscan and killed when the listing is done: a probe asks one question
// and calls no tools. Everything after the listing is the same pipeline a file scan runs.
func probeCommand(dbPath *string) *cobra.Command {
	var serverID string

	command := &cobra.Command{
		Use:   "probe -- <server command> [args...]",
		Short: "Ask a live MCP server what tools it exposes, and record the verdict locally",
		Long: "Starts the server, performs the MCP handshake, reads its tool list, and shuts it down. " +
			"No tool is called and nothing is written anywhere but the local catalogue. Everything " +
			"after the listing is the same classification and injection scan a file scan runs.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tools, err := probe.Tools(cmd.Context(), args[0], args[1:]...)
			if err != nil {
				return err
			}
			source := args[0]
			if len(args) > 1 {
				source += " (and its arguments)"
			}
			return analyse(cmd, *dbPath, serverID, source, tools)
		},
	}

	command.Flags().StringVar(&serverID, "id", "probed", "the server's identity in the catalogue")
	return command
}

// dbCommand browses the catalogue: everything scanned, and one server in detail.
func dbCommand(dbPath *string) *cobra.Command {
	db := &cobra.Command{
		Use:   "db",
		Short: "Browse the local catalogue of scanned servers",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "Every scanned server, riskiest first",
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalogue.Open(*dbPath)
			if err != nil {
				return err
			}
			defer cat.Close()

			servers, err := cat.Servers()
			if err != nil {
				return err
			}
			views := make([]report.Server, 0, len(servers))
			for _, server := range servers {
				tools, err := cat.Tools(server.ID)
				if err != nil {
					return err
				}
				findings, err := cat.Findings(server.ID)
				if err != nil {
					return err
				}
				views = append(views, report.Server{
					ID: server.ID, Source: server.Source, Tools: tools, Findings: findings,
				})
			}
			return report.WriteSummary(cmd.OutOrStdout(), views)
		},
	}

	show := &cobra.Command{
		Use:   "show <id>",
		Short: "One server's full report from the catalogue",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalogue.Open(*dbPath)
			if err != nil {
				return err
			}
			defer cat.Close()

			tools, err := cat.Tools(args[0])
			if err != nil {
				return err
			}
			findings, err := cat.Findings(args[0])
			if err != nil {
				return err
			}
			source, err := cat.Source(args[0])
			if err != nil {
				return err
			}
			return report.Write(cmd.OutOrStdout(), report.Server{
				ID: args[0], Source: source, Tools: tools, Findings: findings,
			})
		},
	}

	db.AddCommand(list, show)
	return db
}

// namesCommand checks package names against a registry before anything installs them.
func namesCommand() *cobra.Command {
	var base string

	command := &cobra.Command{
		Use:   "names <name> [name...]",
		Short: "Check whether package names exist, for slopsquatting",
		Long: "Looks each name up in a package registry and says which do not exist. A name an " +
			"agent suggested that no registry has ever heard of is the shape of a slopsquat: " +
			"publishing under it is trivial once something asks for it.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			results := registry.Checker{Base: base}.CheckAll(args)
			missing := 0
			for _, result := range results {
				switch {
				case result.Error != "":
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s unknown (%s)\n", result.Name, result.Error)
				case !result.Exists:
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s DOES NOT EXIST — do not install\n", result.Name)
					missing++
				default:
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s exists\n", result.Name)
				}
			}
			if missing > 0 {
				return fmt.Errorf("%d name(s) do not exist", missing)
			}
			return nil
		},
	}

	command.Flags().StringVar(&base, "registry", "https://registry.npmjs.org", "registry package-info endpoint")
	return command
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "slopscan %s\n", version)
		},
	}
}