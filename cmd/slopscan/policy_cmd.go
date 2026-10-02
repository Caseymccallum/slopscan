package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Caseymccallum/slopscan/internal/catalogue"
	"github.com/Caseymccallum/slopscan/internal/policy"
)

// policyCommand writes a tapelog policy pack from a scan: the verdicts this tool found, expressed
// as the rules tapelog enforces mid-call. Generated policy is a starting point to edit and test -
// the point is that nobody re-types what the scan already knows.
func policyCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "policy <id>",
		Short: "Write a tapelog policy pack from a server's scan",
		Long: "Translates the catalogue's verdicts for one server into a tapelog policy pack: tools " +
			"with hostile metadata are denied, destructive/financial/execute tools are confirmed, " +
			"clean read-only tools are allowed, and anything unlisted meets a person. The output is " +
			"a starting point - edit it for your estate and validate it with tapelog policy test.",
		Args: cobra.ExactArgs(1),
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
			if len(tools) == 0 {
				return fmt.Errorf("no scan recorded for %s", args[0])
			}
			findings, err := cat.Findings(args[0])
			if err != nil {
				return err
			}
			source, err := cat.Source(args[0])
			if err != nil {
				return err
			}

			return policy.Render(cmd.OutOrStdout(), args[0], source,
				policy.Build(args[0], source, tools, findings))
		},
	}
}