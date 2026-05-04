package identity

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
)

func ParseRecipient(s string, ui *plugin.ClientUI) (age.Recipient, error) {
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

func ParseIdentityFile(name string, ui *plugin.ClientUI) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	b := bufio.NewReader(f)
	p, _ := b.Peek(14)
	peeked := string(p)

	if peeked == "-----BEGIN" {
		const sizeLimit = 1 << 14
		contents, err := io.ReadAll(io.LimitReader(b, sizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		return parseSSHIdentity(name, contents)
	}

	return parseIdentities(b, ui)
}

func parseIdentities(f io.Reader, ui *plugin.ClientUI) ([]age.Identity, error) {
	const sizeLimit = 1 << 24
	var ids []age.Identity
	scanner := bufio.NewScanner(io.LimitReader(f, sizeLimit))
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
		i, err := parseIdentity(line, ui)
		if err != nil {
			if strings.HasPrefix(line, "age1") {
				return nil, fmt.Errorf("error at line %d: apparent recipient found in identities file", n)
			}
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)
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

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}
	return []age.Identity{id}, nil
}
