package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

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
// and fingerprints only, and belongs in the repository beside the cache it
// describes.
const stampName = ".recipients"

const (
	// pluginStampPrefix marks a stamped identity as a fingerprint rather than
	// a recipient, so the two can never be compared as equal by accident.
	pluginStampPrefix = "plugin:"

	// legacyPluginIdentity is what older kix stamped for any plugin identity.
	legacyPluginIdentity = "<identity-based recipient>"
)

// identityRecipient returns the recipient an identity encrypts to and the name
// it takes in the stamp. An unknown type is an error: encrypting without the
// user's own recipient produces files they cannot read.
func identityRecipient(id age.Identity) (age.Recipient, string, error) {
	switch id := id.(type) {
	case *age.X25519Identity:
		r := id.Recipient()
		return r, r.String(), nil
	case *age.HybridIdentity:
		r := id.Recipient()
		return r, r.String(), nil
	case *sshIdentity:
		return id.recipient, id.name(), nil
	case *plugin.Identity:
		// Every identity-derived plugin recipient stringifies alike, and the
		// stamp is committed, so neither can be used as the name.
		return id.Recipient(), pluginStampPrefix + id.Name() + ":" + blake2bHex([]byte(id.String()))[:16], nil
	default:
		return nil, "", fmt.Errorf("identity of type %T is parsed but not supported here: "+
			"kix does not know what it encrypts to, and encrypting without it would "+
			"produce files you cannot read", id)
	}
}

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
) ([]string, error) {
	want, recips, err := recipientSet(m, masterID)
	if err != nil {
		return nil, err
	}

	stampPath := filepath.Join(m.Cache, stampName)
	data, err := os.ReadFile(stampPath)
	switch {
	case os.IsNotExist(err):
		// Nothing to compare against, so assume the sources are consistent and
		// start recording from here. Rewriting every secret on the strength of
		// a missing file would be a bad first impression.
		return nil, writeStamp(stampPath, want)
	case err != nil:
		return nil, fmt.Errorf("reading %q: %w", stampPath, err)
	}

	have := parseStamp(data)

	// An older stamp cannot say whether the token changed, and accusing every
	// upgrader of an unreadable secret on no evidence is worse than missing a
	// rotation that happened before the upgrade.
	upgraded := false
	if have.identity == legacyPluginIdentity && strings.HasPrefix(want.identity, pluginStampPrefix) {
		have.identity = want.identity
		upgraded = true
	}

	if have.equal(want) {
		if upgraded {
			slog.Info("upgrading recipient stamp to fingerprint the plugin identity", "path", stampPath)
			return nil, writeStamp(stampPath, want)
		}
		return nil, nil
	}

	// Decrypting is only possible with whatever the files were written to. If
	// that is the identity we already have, this is just an extraRecipients
	// change and needs nothing from the caller.
	decryptID := masterID
	if have.identity != want.identity {
		if oldIdentityPath == "" {
			return nil, fmt.Errorf(
				"the source secrets are encrypted to %s but flake.kix.identity is now %s, "+
					"so re-encrypting them needs the old identity as well as the new one:\n\n"+
					"    nix run .#kix-seal -- --old-identity /path/to/old-identity.txt\n\n"+
					"you must still hold the old identity; nothing else can read those files",
				have.identity, want.identity)
		}
		idents, err := parseIdentityFile(oldIdentityPath, terminalUI(), askPassphrase)
		if err != nil {
			return nil, fmt.Errorf("parsing --old-identity: %w", err)
		}
		decryptID = idents[0]
		slog.Info("identity rotated, re-encrypting source secrets", "from", have.identity, "to", want.identity)
	} else {
		slog.Info("recipient set changed, re-encrypting source secrets")
	}

	// Three phases, because this rewrites several files and must not leave the
	// repository half converted. Planning fails before anything is touched,
	// decryption carries all of the identity interaction, and the writes then
	// run back to back with nothing slow in between.
	plan, foreign := planRewrites(profiles)
	if len(plan) == 0 {
		return foreign, writeStamp(stampPath, want)
	}

	slog.Info("re-encrypting source secrets", "files", len(plan))
	if _, ok := decryptID.(*plugin.Identity); ok {
		// Worth saying before the prompts start rather than after: a rotation
		// is the one operation whose cost scales with the number of secrets.
		slog.Info("each file is unwrapped separately, so the identity may ask for one confirmation per file",
			"confirmations", len(plan))
	}

	plaintexts, err := decryptRewrites(plan, ciphertexts, decryptID, masterID)
	if err != nil {
		return nil, err
	}

	if err := writeRewrites(plan, plaintexts, recips, ciphertexts); err != nil {
		return nil, err
	}

	return foreign, writeStamp(stampPath, want)
}

// rewrite is one source file to re-encrypt, with every secret that reads it. A
// file shared by several hosts is rewritten once, and each of those secrets
// still needs the new ciphertext or its cache entry keeps the old name.
type rewrite struct {
	sourcePath string
	secretIDs  []string
}

// planRewrites groups the secrets by source file, and separates out the ones
// with no copy in the working tree.
//
// Those are not a configuration problem to be refused: a secret whose `file`
// comes from another flake belongs to whoever maintains that flake, and this
// repository cannot rewrite it however the recipient set changes. They are
// returned rather than dropped, because a recipient added here still cannot
// read them, and only the caller knows when saying so will be seen.
func planRewrites(profiles []*profile.Profile) (plan []rewrite, foreign []string) {
	// A secret shared by several hosts is seen once per host, so both lists
	// collect duplicates and shed them on the way out.
	byPath := make(map[string][]string)
	for _, p := range profiles {
		for id, s := range p.Secrets {
			if s.SourcePath == "" {
				foreign = append(foreign, fmt.Sprintf("%s (%s)", id, s.File))
				continue
			}
			byPath[s.SourcePath] = append(byPath[s.SourcePath], id)
		}
	}
	slices.Sort(foreign)
	foreign = slices.Compact(foreign)

	plan = make([]rewrite, 0, len(byPath))
	for path, ids := range byPath {
		slices.Sort(ids)
		plan = append(plan, rewrite{sourcePath: path, secretIDs: slices.Compact(ids)})
	}
	slices.SortFunc(plan, func(a, b rewrite) int { return strings.Compare(a.sourcePath, b.sourcePath) })
	return plan, foreign
}

// reportForeign names the secrets a recipient change could not reach. Loud,
// because nothing else will say it: the seal succeeds, the stamp records the
// new recipient set for everything this repository owns, and these files stay
// readable only by whoever they were already encrypted to.
func reportForeign(foreign []string) {
	if len(foreign) == 0 {
		return
	}
	slog.Warn("not re-encrypted: these secrets come from outside this flake, " +
		"so the new recipients cannot read them until whoever maintains those files re-encrypts them")
	for _, f := range foreign {
		slog.Warn("owned elsewhere", "secret", f)
	}
}

// decryptRewrites unwraps every source file once, returning the plaintexts by
// source path.
//
// Serial and once per file for the reason decryptOnce documents: a plugin
// identity spawns a fresh process per unwrap around a single unsynchronised
// ClientUI and, often, one piece of hardware.
//
// `fallback` absorbs a run that was interrupted partway through the write
// phase, where some files are already on the new recipient set and cannot be
// read by the old identity. Trying `decryptID` first keeps that fallback free
// in the ordinary case, which matters when each attempt costs a confirmation.
func decryptRewrites(
	plan []rewrite,
	ciphertexts map[string][]byte,
	decryptID, fallback age.Identity,
) (map[string][]byte, error) {
	plaintexts := make(map[string][]byte, len(plan))
	for _, r := range plan {
		ct := ciphertexts[r.secretIDs[0]]
		plaintext, err := secure.DecryptAge(ct, decryptID)
		if err != nil && fallback != decryptID {
			if alt, altErr := secure.DecryptAge(ct, fallback); altErr == nil {
				slog.Debug("already re-encrypted by an earlier run", "path", r.sourcePath)
				plaintext, err = alt, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("decrypting %q for re-encryption: %w", r.sourcePath, err)
		}
		plaintexts[r.sourcePath] = plaintext
	}
	return plaintexts, nil
}

// writeRewrites encrypts to the new recipients and writes every source file.
//
// Nothing here waits on the user, so the window in which the working tree is
// half converted is a handful of file writes rather than the whole rotation.
// Should it still be interrupted, re-running is safe: decryptRewrites reads
// back whatever each file ended up as.
func writeRewrites(
	plan []rewrite,
	plaintexts map[string][]byte,
	recips []age.Recipient,
	ciphertexts map[string][]byte,
) error {
	for _, r := range plan {
		reencrypted, err := secure.EncryptAge(plaintexts[r.sourcePath], recips...)
		if err != nil {
			return fmt.Errorf("re-encrypting %q: %w", r.sourcePath, err)
		}
		if err := os.WriteFile(r.sourcePath, reencrypted, 0o644); err != nil {
			return fmt.Errorf("writing %q: %w", r.sourcePath, err)
		}
		for _, id := range r.secretIDs {
			ciphertexts[id] = reencrypted
		}
		slog.Info("re-encrypted", "path", r.sourcePath)
	}
	return nil
}

func writeStamp(path string, s stamp) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %q: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(s.String()), 0o644); err != nil {
		return fmt.Errorf("writing %q: %w", path, err)
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
	r, idStamp, err := identityRecipient(masterID)
	if err != nil {
		return stamp{}, nil, err
	}
	recips = append(recips, r)
	s.identity = idStamp

	for _, name := range m.ExtraRecipients {
		r, err := parseRecipient(name, terminalUI())
		if err != nil {
			return stamp{}, nil, fmt.Errorf("parsing recipient %q: %w", name, err)
		}
		recips = append(recips, r)
		s.extra = append(s.extra, name)
	}

	slices.Sort(s.extra)
	return s, recips, nil
}
