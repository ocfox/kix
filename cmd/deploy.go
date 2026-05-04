package cmd

import (
	"github.com/spf13/cobra"
)

var early bool

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Decrypt and deploy cipher credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDeploy(early)
	},
}

func init() {
	deployCmd.Flags().BoolVarP(&early, "early", "e", false, "deploy before users init")
}
