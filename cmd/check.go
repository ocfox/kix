package cmd

import (
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check secret status",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCheck()
	},
}
