// Command slopscan is a local scanner for MCP server risk.
//
// It reads a server's tool list, classifies what each tool can do, scans the metadata for prompt
// injection, checks package names against a registry before anything installs them, and keeps
// every verdict in a local SQLite catalogue. Nothing here phones home: the catalogue is the point,
// and it belongs to whoever runs the scan.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Caseymccallum/slopscan/internal/catalogue"
	"github.com/Caseymccallum/slopscan/internal/drift"
	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/probe"
	"github.com/Caseymccallum/slopscan/internal/registry"
	"github.com/Caseymccallum/slopscan/internal/report"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

const version = "0.2.0"

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

	root.AddCommand(
		scanCommand(&dbPath), probeCommand(&dbPath), dbCommand(&dbPath),
		pinCommand(&dbPath), driftCommand(&dbPath), namesCommand(), versionCommand(),
	)
	if err := root.Execute(); err != nil {
		// Exit 3 for a broken baseline contract (the signal CI greps for), 1 for everything else.
		var breaking *BreakingError
		if errors.As(err, &breaking) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

// BreakingError marks "the server's tools changed in a way that breaks the reviewed baseline" -
// distinct from a plain failure so a script can tell a rug pull from a typo.
type BreakingError struct{ Message string }

func (e *BreakingError) Error() string { return e.Message }

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
//
// When a baseline has been pinned for this server, the same pass also compares against it and says
// so in the report - because the moment that matters is the second scan, not the first.
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
	if err := cat.Record(serverID, source, tools, assessments, findings); err != nil {
		return err
	}

	if err := report.Write(cmd.OutOrStdout(), report.Server{
		ID: serverID, Source: source, Tools: assessments, Findings: findings,
	}); err != nil {
		return err
	}

	return reportDrift(cmd, cat, serverID, tools)
}

// reportDrift compares this scan with the pinned baseline, if there is one. A first scan against
// no baseline says nothing; every later one answers the only question that matters after review:
// is the server still saying what it said when it was approved?
func reportDrift(cmd *cobra.Command, cat *catalogue.Catalogue, serverID string, current []risk.Tool) error {
	baseline, err := cat.Baseline(serverID)
	if err != nil || len(baseline) == 0 {
		return err
	}

	comparison := drift.Compare(baseline, current)
	if !comparison.Drifted {
		fmt.Fprintf(cmd.OutOrStdout(), "\nvs pinned baseline: unchanged (%d tools).\n", comparison.Unchanged)
		return nil
	}

	if err := report.WriteDrift(cmd.OutOrStdout(), comparison); err != nil {
		return err
	}
	// The same contract as the drift command: a breaking change fails the run, so CI stops on a
	// rug pull instead of printing a warning nobody reads.
	if comparison.Breaking {
		return &BreakingError{Message: "breaking changes against the pinned baseline"}
	}
	return nil
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

// pinCommand freezes a server's current tool surface as the reviewed baseline; driftCommand
// compares what is in the catalogue now against that baseline and says what changed.
func pinCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "pin <id>",
		Short: "Freeze a server's current tools as the reviewed baseline",
		Long: "Records what is in the catalogue right now as the copy every later scan of this " +
			"server is compared against. Pinning is a deliberate act - the baseline changes only " +
			"when you run this again - which is what makes a later difference meaningful.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalogue.Open(*dbPath)
			if err != nil {
				return err
			}
			defer cat.Close()

			if err := cat.Pin(args[0]); err != nil {
				return err
			}
			baseline, err := cat.Baseline(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Pinned %d tool(s) as the baseline for %s.\n", len(baseline), args[0])
			return nil
		},
	}
}

// driftCommand answers the question a re-scan raises: is the server still saying what it said
// when it was approved? It reads both sides from the catalogue, so it works in CI without
// touching the server at all.
func driftCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "drift <id>",
		Short: "Compare a server's current tools against its pinned baseline",
		Long: "Reads the latest scan and the pinned baseline from the catalogue and reports every " +
			"addition, removal and change. Exit code 3 means a breaking change - a tool removed, " +
		"renamed, or a description rewritten - which is the shape of a rug pull as well as of " +
			"ordinary breakage. Scan again first if the catalogue is stale.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := catalogue.Open(*dbPath)
			if err != nil {
				return err
			}
			defer cat.Close()

			baseline, err := cat.Baseline(args[0])
			if err != nil {
				return err
			}
			if len(baseline) == 0 {
				return fmt.Errorf("no pinned baseline for %s - run slopscan pin %s after a scan", args[0], args[0])
			}
			current, err := cat.Definitions(args[0])
			if err != nil {
				return err
			}

			comparison := drift.Compare(baseline, current)
			if !comparison.Drifted {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: unchanged against its pinned baseline (%d tools).\n", args[0], comparison.Unchanged)
				return nil
			}
			if err := report.WriteDrift(cmd.OutOrStdout(), comparison); err != nil {
				return err
			}
			if comparison.Breaking {
				return &BreakingError{Message: "breaking changes against the pinned baseline"}
			}
			return nil
		},
	}
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