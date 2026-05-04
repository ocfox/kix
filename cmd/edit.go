package cmd

import (
	"github.com/spf13/cobra"
)

var (
	editIdentity   string
	editRecipients []string
)

var editCmd = &cobra.Command{
	Use:   "edit <file>",
	Short: "Edit encrypted file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEdit(args[0], editIdentity, editRecipients)
	},
}

func init() {
	editCmd.Flags().StringVarP(&editIdentity, "identity", "i", "", "identity for decryption")
	editCmd.Flags().StringSliceVarP(&editRecipients, "recipient", "r", nil, "recipients for re-encryption (can be repeated)")
}
