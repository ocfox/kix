package cmd

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"

	"github.com/ocfox/kix/secure"
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

func runEdit(file, identityPath string, recipients []string) error {
	ui := terminalUI()

	idents, err := parseIdentityFile(identityPath, ui)
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}
	masterID := idents[0]

	var recips []age.Recipient
	if r := identityRecipient(masterID); r != nil {
		recips = append(recips, r)
	}
	for _, r := range recipients {
		recip, err := parseRecipient(r, ui)
		if err != nil {
			return fmt.Errorf("parsing recipient %q: %w", r, err)
		}
		recips = append(recips, recip)
	}

	tmp, err := os.CreateTemp("", "kix-edit-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	var preHash string
	existing := true
	if _, err := os.Stat(file); os.IsNotExist(err) {
		existing = false
	} else {
		encrypted, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}
		plaintext, err := secure.DecryptAge(encrypted, masterID)
		if err != nil {
			return fmt.Errorf("decrypting: %w", err)
		}
		preHash = blake2bHex(plaintext)
		if _, err := tmp.Write(plaintext); err != nil {
			tmp.Close()
			return fmt.Errorf("writing temp: %w", err)
		}
	}
	tmp.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}
	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("reading edited: %w", err)
	}

	if !existing && len(edited) == 0 {
		slog.Info("no content written, nothing to do")
		return nil
	}
	if existing && blake2bHex(edited) == preHash {
		slog.Info("file unchanged")
		return nil
	}

	encrypted, err := secure.EncryptAge(edited, recips...)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	if err := os.WriteFile(file, encrypted, 0o644); err != nil {
		return fmt.Errorf("writing encrypted file: %w", err)
	}

	if existing {
		slog.Info("edited and re-encrypted", "path", file)
	} else {
		slog.Info("created encrypted file", "path", file)
	}
	return nil
}

func identityRecipient(id age.Identity) age.Recipient {
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient()
	case *plugin.Identity:
		return id.Recipient()
	default:
		return nil
	}
}

func blake2bHex(data []byte) string {
	h, _ := blake2b.New256(nil)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
