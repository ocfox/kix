package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	profiles  []string
	flakeRoot string
)

var rootCmd = &cobra.Command{
	Use:   "kix",
	Short: "Secret manager for NixOS",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&profiles, "profile", "p", nil, "secret profile (can be repeated)")
	rootCmd.PersistentFlags().StringVarP(&flakeRoot, "flake-root", "f", ".", "toplevel of flake repository")

	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(deployCmd)
	rootCmd.AddCommand(checkCmd)
}
