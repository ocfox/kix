package cmd

import (
	"github.com/spf13/cobra"
)

var sealIdentity string
var sealCache string

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Re-encrypt secrets for each host",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSeal(sealIdentity, sealCache)
	},
}

func init() {
	sealCmd.Flags().StringVarP(&sealIdentity, "identity", "i", "", "identity for decrypt secrets")
	sealCmd.Flags().StringVarP(&sealCache, "cache", "c", "", "cache directory for re-encrypted outputs")
	sealCmd.MarkFlagRequired("identity")
	sealCmd.MarkFlagRequired("cache")
}
