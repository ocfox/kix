package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/ocfox/kix/manifest"
	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

// stampName records, next to the cache, which recipients the source .age files
// were last written to.
//
// An age file does not say who it is encrypted to: the header carries one
// opaque stanza per recipient, and nothing in it identifies the recipient. You
// can count stanzas, which catches adding one but not swapping one, so the
// recipient set has to be remembered rather than derived. It holds public keys
// only, and belongs in the repository beside the cache it describes.
const stampName = ".recipients"

// stamp keeps the identity's own recipient apart from the extra ones, because
// the two kinds of change need different handling: extras can be applied with
// the identity we already have, while a changed identity means the existing
// files were encrypted to a key this run does not hold.
type stamp struct {
	identity string
	extra    []string
}

func (s stamp) String() string {
	var b strings.Builder
	if s.identity != "" {
		fmt.Fprintf(&b, "identity %s\n", s.identity)
	}
	for _, r := range s.extra {
		fmt.Fprintf(&b, "recipient %s\n", r)
	}
	return b.String()
}

func parseStamp(data []byte) stamp {
	var s stamp
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch name {
		case "identity":
			s.identity = value
		case "recipient":
			s.extra = append(s.extra, value)
		}
	}
	return s
}

func (s stamp) equal(other stamp) bool { return s.String() == other.String() }

// refreshRecipients re-encrypts the source secrets when the recipient set has
// changed since the last seal, and updates ciphertexts in place so the rest of
// the run plans against what it just wrote rather than the now-stale copies in
// the store.
func refreshRecipients(
	m *manifest.Manifest,
	masterID age.Identity,
	oldIdentityPath string,
	profiles []*profile.Profile,
	ciphertexts map[string][]byte,
) error {
	want, recips, err := recipientSet(m, masterID)
	if err != nil {
		return err
	}

	stampPath := filepath.Join(m.Cache, stampName)
	data, err := os.ReadFile(stampPath)
	switch {
	case os.IsNotExist(err):
		// Nothing to compare against, so assume the sources are consistent and
		// start recording from here. Rewriting every secret on the strength of
		// a missing file would be a bad first impression.
		return writeStamp(stampPath, want)
	case err != nil:
		return fmt.Errorf("reading %s: %w", stampPath, err)
	}

	have := parseStamp(data)
	if have.equal(want) {
		return nil
	}

	// Decrypting is only possible with whatever the files were written to. If
	// that is the identity we already have, this is just an extraRecipients
	// change and needs nothing from the caller.
	decryptID := masterID
	if have.identity != want.identity {
		if oldIdentityPath == "" {
			return fmt.Errorf(
				"the source secrets are encrypted to %s but flake.kix.identity is now %s, "+
					"so re-encrypting them needs the old identity as well as the new one:\n\n"+
					"    nix run .#kix-seal -- --old-identity /path/to/old-identity.txt\n\n"+
					"you must still hold the old identity; nothing else can read those files",
				have.identity, want.identity)
		}
		idents, err := parseIdentityFile(oldIdentityPath, terminalUI())
		if err != nil {
			return fmt.Errorf("parsing --old-identity: %w", err)
		}
		decryptID = idents[0]
		slog.Info("identity rotated, re-encrypting source secrets", "from", have.identity, "to", want.identity)
	} else {
		slog.Info("recipient set changed, re-encrypting source secrets")
	}

	// One source file can appear under several hosts; rewrite each once, then
	// give every secret that shares it the new ciphertext, or its cache entry
	// would still be named after the old one.
	written := make(map[string][]byte)
	for _, p := range profiles {
		for id, s := range p.Secrets {
			if s.SourcePath == "" {
				slog.Warn("cannot re-encrypt: file is outside secretsDir", "secret", id, "file", s.File)
				continue
			}
			if reencrypted, done := written[s.SourcePath]; done {
				ciphertexts[id] = reencrypted
				continue
			}

			plaintext, err := secure.DecryptAge(ciphertexts[id], decryptID)
			if err != nil {
				return fmt.Errorf("decrypting %s for re-encryption: %w", id, err)
			}
			reencrypted, err := secure.EncryptAge(plaintext, recips...)
			if err != nil {
				return fmt.Errorf("re-encrypting %s: %w", id, err)
			}
			if err := os.WriteFile(s.SourcePath, reencrypted, 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", s.SourcePath, err)
			}
			written[s.SourcePath] = reencrypted
			ciphertexts[id] = reencrypted
			slog.Info("re-encrypted", "secret", id, "path", s.SourcePath)
		}
	}

	return writeStamp(stampPath, want)
}

func writeStamp(path string, s stamp) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(s.String()), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// recipientSet returns the recipients source secrets should be encrypted to,
// and the stamp describing them.
func recipientSet(m *manifest.Manifest, masterID age.Identity) (stamp, []age.Recipient, error) {
	var (
		s      stamp
		recips []age.Recipient
	)
	if r := identityRecipient(masterID); r != nil {
		recips = append(recips, r)
		s.identity = fmt.Sprint(r)
	}
	for _, name := range m.ExtraRecipients {
		r, err := parseRecipient(name, terminalUI())
		if err != nil {
			return stamp{}, nil, fmt.Errorf("parsing recipient %q: %w", name, err)
		}
		recips = append(recips, r)
		s.extra = append(s.extra, name)
	}
	if len(recips) == 0 {
		return stamp{}, nil, fmt.Errorf("no recipients: the identity has none of its own and no extraRecipients are set")
	}

	sort.Strings(s.extra)
	return s, recips, nil
}
