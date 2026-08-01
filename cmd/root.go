package cmd

import (
	"bufio"
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

func Execute() {
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
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	b := bufio.NewReader(f)
	p, _ := b.Peek(14)

	if string(p) == "-----BEGIN" {
		const sizeLimit = 1 << 14
		contents, err := io.ReadAll(io.LimitReader(b, sizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		id, err := agessh.ParseIdentity(contents)
		if err != nil {
			return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
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
			return nil, fmt.Errorf("identities file is not valid UTF-8")
		}
		id, err := parseIdentity(line, ui)
		if err != nil {
			if strings.HasPrefix(line, "age1") {
				return nil, fmt.Errorf("line %d: apparent recipient in identities file", n)
			}
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read identities file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found")
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
		return nil, fmt.Errorf("unknown identity type")
	}
}
