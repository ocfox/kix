package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"

	"github.com/ocfox/kix/manifest"
	"github.com/ocfox/kix/secure"
)

var (
	editManifest   string
	editIdentity   string
	editRecipients []string
)

var editCmd = &cobra.Command{
	Use:   "edit <file>",
	Short: "Edit encrypted file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEdit(args[0], editManifest, editIdentity, editRecipients)
	},
}

func init() {
	editCmd.Flags().StringVarP(&editManifest, "manifest", "m", "", "manifest to take identity and recipients from")
	editCmd.Flags().StringVarP(&editIdentity, "identity", "i", "", "identity for decryption (overrides --manifest)")
	editCmd.Flags().StringSliceVarP(&editRecipients, "recipient", "r", nil, "extra recipients for re-encryption (overrides --manifest, can be repeated)")
}

func runEdit(file, manifestPath, identityPath string, recipients []string) error {
	ui := terminalUI()

	if manifestPath != "" {
		m, err := manifest.Load(manifestPath)
		if err != nil {
			return err
		}
		if identityPath == "" {
			identityPath = m.Identity
		}
		if recipients == nil {
			recipients = m.ExtraRecipients
		}
	}
	if identityPath == "" {
		return errors.New("no identity: pass --identity or --manifest")
	}

	idents, err := parseIdentityFile(identityPath, ui, askPassphrase)
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}
	masterID := idents[0]

	ownRecip, _, err := identityRecipient(masterID)
	if err != nil {
		return err
	}
	recips := []age.Recipient{ownRecip}
	for _, r := range recipients {
		recip, err := parseRecipient(r, ui)
		if err != nil {
			return fmt.Errorf("parsing recipient %q: %w", r, err)
		}
		recips = append(recips, recip)
	}

	// Before the editor rather than after. Everything typed into it is lost if
	// the write at the end fails, and a missing parent directory is how that
	// happens: secretsDir does not exist yet in a fresh repository, so the
	// very first secret would be typed out and thrown away.
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return fmt.Errorf("creating the directory for %q: %w", file, err)
	}

	tmp, err := createPlaintextFile(plaintextDir())
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
	if err := writeFileAtomic(file, encrypted, 0o644); err != nil {
		return err
	}

	if existing {
		slog.Info("edited and re-encrypted", "path", file)
	} else {
		slog.Info("created encrypted file", "path", file)
	}
	return nil
}

// writeFileAtomic replaces path in a single step.
//
// By the time this runs the plaintext exists nowhere else: the editor's copy
// is removed as this function returns, so the file being replaced holds the
// only other copy of the secret. A partial write over it would take both.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	// Alongside the target, so the rename stays within one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary file next to %q: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	// Closed explicitly below; this one only catches the paths that return
	// before getting there.
	defer tmp.Close()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing %q: %w", tmp.Name(), err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %q: %w", tmp.Name(), err)
	}
	// The rename is only atomic with respect to the file's contents once those
	// contents have reached the filesystem.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing %q: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %q: %w", tmp.Name(), err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replacing %q: %w", path, err)
	}
	return nil
}

func blake2bHex(data []byte) string {
	h, _ := blake2b.New256(nil)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
