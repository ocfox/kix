// Package cmd implements the kix command line: seal, edit, deploy and check,
// along with the recipient and identity parsing they share.
package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var rootCmd = &cobra.Command{
	Use:   "kix",
	Short: "Secret manager for NixOS",
}

// Execute runs the root command. Errors are already reported by cobra, so it
// only sets the exit status.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(deployCmd)
	rootCmd.AddCommand(checkCmd)
}

func terminalUI() *plugin.ClientUI {
	return plugin.NewTerminalUI(
		func(format string, v ...any) { fmt.Printf(format, v...) },
		func(format string, v ...any) { fmt.Fprintf(os.Stderr, format, v...) },
	)
}

func parseRecipient(s string, ui *plugin.ClientUI) (age.Recipient, error) {
	if strings.HasPrefix(s, "ssh-") {
		return agessh.ParseRecipient(s)
	}
	if strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1 {
		return plugin.NewRecipient(s, ui)
	}
	if strings.HasPrefix(s, "age1") {
		return age.ParseX25519Recipient(s)
	}
	return nil, fmt.Errorf("unknown recipient type: %q", s)
}

// passphraseFunc reads one secret from the user. desc says what is being
// unlocked, prompt labels the input itself.
type passphraseFunc func(desc, prompt string) ([]byte, error)

func parseIdentityFile(name string, ui *plugin.ClientUI, ask passphraseFunc) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening identities file %q: %w", name, err)
	}
	defer f.Close()

	return parseIdentities(bufio.NewReader(f), name, ui, ask)
}

func parseIdentities(b *bufio.Reader, name string, ui *plugin.ClientUI, ask passphraseFunc) ([]age.Identity, error) {
	p, _ := b.Peek(len(armorHeader))

	// An `age -p` identity file is itself an age file, and armored it also
	// opens with -----BEGIN, so this has to be checked before SSH.
	if isAgeEncrypted(p) {
		return parseEncryptedIdentityFile(b, name, ui, ask)
	}

	if bytes.HasPrefix(p, []byte("-----BEGIN")) {
		const sizeLimit = 1 << 14
		contents, err := io.ReadAll(io.LimitReader(b, sizeLimit))
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", name, err)
		}
		id, err := parseSSHIdentity(contents, name, ask)
		if err != nil {
			return nil, err
		}
		return []age.Identity{id}, nil
	}

	const sizeLimit = 1 << 24
	var ids []age.Identity
	scanner := bufio.NewScanner(io.LimitReader(b, sizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, errors.New("identities file is not valid UTF-8")
		}
		id, err := parseIdentity(line, ui)
		if err != nil {
			if strings.HasPrefix(line, "age1") {
				return nil, fmt.Errorf("line %d: apparent recipient in identities file", n)
			}
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading identities file %q: %w", name, err)
	}
	if len(ids) == 0 {
		return nil, errors.New("no identities found")
	}
	return ids, nil
}

const armorHeader = "-----BEGIN AGE ENCRYPTED FILE-----"

func isAgeEncrypted(p []byte) bool {
	return bytes.HasPrefix(p, []byte(armorHeader)) ||
		bytes.HasPrefix(p, []byte("age-encryption.org/v1"))
}

// parseEncryptedIdentityFile unlocks an identity file that was itself
// encrypted under a passphrase, then parses what was inside.
func parseEncryptedIdentityFile(b *bufio.Reader, name string, ui *plugin.ClientUI, ask passphraseFunc) ([]age.Identity, error) {
	pass, err := ask(fmt.Sprintf("Unlocking the identity file %s.", name), "Passphrase:")
	if err != nil {
		return nil, err
	}
	id, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}

	var src io.Reader = b
	if p, _ := b.Peek(len(armorHeader)); bytes.HasPrefix(p, []byte(armorHeader)) {
		src = armor.NewReader(b)
	}
	plain, err := age.Decrypt(src, id)
	if err != nil {
		return nil, fmt.Errorf("incorrect passphrase for %q", name)
	}
	// The decrypted file is an ordinary identity file, but not another
	// encrypted one: nesting would just mean prompting twice.
	ids, err := parseIdentities(bufio.NewReader(plain), name, ui, refusePassphrase)
	if err != nil {
		return nil, err
	}
	return ids, nil
}

func refusePassphrase(desc, prompt string) ([]byte, error) {
	return nil, errors.New("identity file is encrypted inside an encrypted identity file")
}

// parseSSHIdentity handles both plain and passphrase-protected private keys.
func parseSSHIdentity(contents []byte, name string, ask passphraseFunc) (age.Identity, error) {
	id, err := agessh.ParseIdentity(contents)
	if err == nil {
		return id, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("parsing SSH identity in %q: %w", name, err)
	}
	if missing.PublicKey == nil {
		return nil, fmt.Errorf("%q is encrypted and carries no public key", name)
	}
	// The passphrase is only requested if a stanza actually matches this key.
	return agessh.NewEncryptedSSHIdentity(missing.PublicKey, contents, func() ([]byte, error) {
		return ask(fmt.Sprintf("Unlocking the SSH key %s.", name), "Passphrase:")
	})
}

func parseIdentity(s string, ui *plugin.ClientUI) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, ui)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1"):
		return age.ParseHybridIdentity(s)
	default:
		return nil, errors.New("unknown identity type")
	}
}
