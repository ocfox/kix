// Package cmd implements the kix command line: seal, edit, deploy and check,
// along with the recipient and identity parsing they share.
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"github.com/spf13/cobra"
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

func parseIdentityFile(name string, ui *plugin.ClientUI) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening identities file %q: %w", name, err)
	}
	defer f.Close()

	b := bufio.NewReader(f)
	p, _ := b.Peek(14)

	if string(p) == "-----BEGIN" {
		const sizeLimit = 1 << 14
		contents, err := io.ReadAll(io.LimitReader(b, sizeLimit))
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", name, err)
		}
		id, err := agessh.ParseIdentity(contents)
		if err != nil {
			return nil, fmt.Errorf("parsing SSH identity in %q: %w", name, err)
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
