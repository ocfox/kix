package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ocfox/kix/manifest"
	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

// pluginIdentity builds a plugin identity without a plugin binary. Only Unwrap
// spawns one, and none of the stamp logic gets that far.
func pluginIdentity(t *testing.T, name string, data []byte) *plugin.Identity {
	t.Helper()
	encoded := plugin.EncodeIdentity(name, data)
	if encoded == "" {
		t.Fatalf("EncodeIdentity(%q) returned empty", name)
	}
	id, err := plugin.NewIdentity(encoded, nil)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	return id
}

func stampNameFor(t *testing.T, id age.Identity) string {
	t.Helper()
	_, name, err := identityRecipient(id)
	if err != nil {
		t.Fatalf("identityRecipient: %v", err)
	}
	return name
}

// Two hardware tokens must not stamp alike.
func TestIdentityStampDistinguishesPluginIdentities(t *testing.T) {
	a := stampNameFor(t, pluginIdentity(t, "yubikey", []byte{1, 2, 3}))
	b := stampNameFor(t, pluginIdentity(t, "yubikey", []byte{4, 5, 6}))

	if a == b {
		t.Errorf("two plugin identities stamped alike: %q", a)
	}
	if strings.Contains(a, legacyPluginIdentity) {
		t.Errorf("stamp is the placeholder, not a fingerprint: %q", a)
	}
	if !strings.HasPrefix(a, pluginStampPrefix) {
		t.Errorf("stamp %q lacks the %q prefix that keeps it from colliding with a recipient", a, pluginStampPrefix)
	}
}

func TestIdentityStampIsStable(t *testing.T) {
	first := stampNameFor(t, pluginIdentity(t, "yubikey", []byte{1, 2, 3}))
	second := stampNameFor(t, pluginIdentity(t, "yubikey", []byte{1, 2, 3}))

	if first != second {
		t.Errorf("same identity stamped %q then %q", first, second)
	}
}

// The stamp is committed, so it must carry a fingerprint rather than the
// identity itself.
func TestIdentityStampWithholdsTheIdentityEncoding(t *testing.T) {
	id := pluginIdentity(t, "yubikey", []byte{1, 2, 3})

	if got := stampNameFor(t, id); strings.Contains(got, id.String()) {
		t.Errorf("stamp %q contains the identity encoding", got)
	}
}

func TestIdentityStampX25519UsesTheRecipient(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := stampNameFor(t, id), id.Recipient().String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// refreshStamp exercises refreshRecipients with no profiles, so it stops at the
// stamp comparison and never needs to decrypt anything.
func refreshStamp(t *testing.T, cache string, id age.Identity) error {
	t.Helper()
	_, err := refreshRecipients(&manifest.Manifest{Cache: cache}, id, "", nil, nil)
	return err
}

func writeStampFile(t *testing.T, cache, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cache, stampName), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readStampFile(t *testing.T, cache string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cache, stampName))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The regression itself.
func TestRefreshRecipientsDetectsPluginRotation(t *testing.T) {
	cache := t.TempDir()
	old := pluginIdentity(t, "yubikey", []byte{1, 2, 3})
	writeStampFile(t, cache, (stamp{identity: stampNameFor(t, old)}).String())

	err := refreshStamp(t, cache, pluginIdentity(t, "yubikey", []byte{4, 5, 6}))
	if err == nil {
		t.Fatal("rotating to a different plugin identity was accepted; the sources are still encrypted to the old token")
	}
	if !strings.Contains(err.Error(), "--old-identity") {
		t.Errorf("error does not tell the user how to proceed: %v", err)
	}
}

func TestRefreshRecipientsAcceptsUnchangedPluginIdentity(t *testing.T) {
	cache := t.TempDir()
	id := pluginIdentity(t, "yubikey", []byte{1, 2, 3})
	want := (stamp{identity: stampNameFor(t, id)}).String()
	writeStampFile(t, cache, want)

	if err := refreshStamp(t, cache, id); err != nil {
		t.Fatalf("unchanged identity rejected: %v", err)
	}
	if got := readStampFile(t, cache); got != want {
		t.Errorf("stamp rewritten to %q, want %q", got, want)
	}
}

// An older stamp cannot say whether the token changed, so the upgrade must pass
// rather than accuse, and must still leave a fingerprint behind.
func TestRefreshRecipientsUpgradesLegacyStamp(t *testing.T) {
	cache := t.TempDir()
	id := pluginIdentity(t, "yubikey", []byte{1, 2, 3})
	writeStampFile(t, cache, (stamp{identity: legacyPluginIdentity}).String())

	if err := refreshStamp(t, cache, id); err != nil {
		t.Fatalf("legacy stamp rejected: %v", err)
	}

	got := readStampFile(t, cache)
	if strings.Contains(got, legacyPluginIdentity) {
		t.Fatalf("legacy placeholder left in place: %q", got)
	}
	want := (stamp{identity: stampNameFor(t, id)}).String()
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	if err := refreshStamp(t, cache, pluginIdentity(t, "yubikey", []byte{4, 5, 6})); err == nil {
		t.Error("rotation after the upgrade went unnoticed")
	}
}

// The placeholder must not be treated as a wildcard for an X25519 identity: a
// plugin identity really was swapped for a bare key there.
func TestRefreshRecipientsDoesNotUpgradeLegacyStampToX25519(t *testing.T) {
	cache := t.TempDir()
	writeStampFile(t, cache, (stamp{identity: legacyPluginIdentity}).String())

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := refreshStamp(t, cache, id); err == nil {
		t.Error("swapping a plugin identity for an X25519 one went unnoticed")
	}
}

func x25519(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func writeIdentityFile(t *testing.T, dir string, id *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeSecret encrypts contents to r and drops it in dir, returning the path
// and the ciphertext seal would have read.
func writeSecret(t *testing.T, dir, name, contents string, r age.Recipient) (string, []byte) {
	t.Helper()
	ct, err := secure.EncryptAge([]byte(contents), r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, ct, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, ct
}

func decryptFile(t *testing.T, path string, id age.Identity) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := secure.DecryptAge(data, id)
	if err != nil {
		t.Fatalf("decrypting %q: %v", path, err)
	}
	return string(plaintext)
}

// A rotation interrupted partway through leaves some files on the new identity
// and some on the old, and the stamp unwritten. Re-running must converge rather
// than fail on the files it already did.
func TestRefreshRecipientsResumesAnInterruptedRotation(t *testing.T) {
	dir, cache := t.TempDir(), t.TempDir()
	oldID, newID := x25519(t), x25519(t)

	donePath, doneCT := writeSecret(t, dir, "done.age", "already-rotated", newID.Recipient())
	todoPath, todoCT := writeSecret(t, dir, "todo.age", "not-yet-rotated", oldID.Recipient())

	writeStampFile(t, cache, (stamp{identity: oldID.Recipient().String()}).String())

	profiles := []*profile.Profile{{Secrets: map[string]profile.Secret{
		"done": {File: donePath, SourcePath: donePath},
		"todo": {File: todoPath, SourcePath: todoPath},
	}}}
	ciphertexts := map[string][]byte{"done": doneCT, "todo": todoCT}

	_, err := refreshRecipients(
		&manifest.Manifest{Cache: cache}, newID,
		writeIdentityFile(t, dir, oldID), profiles, ciphertexts)
	if err != nil {
		t.Fatalf("re-running an interrupted rotation failed: %v", err)
	}

	if got := decryptFile(t, donePath, newID); got != "already-rotated" {
		t.Errorf("done.age is %q, want %q", got, "already-rotated")
	}
	if got := decryptFile(t, todoPath, newID); got != "not-yet-rotated" {
		t.Errorf("todo.age is %q, want %q", got, "not-yet-rotated")
	}

	want := (stamp{identity: newID.Recipient().String()}).String()
	if got := readStampFile(t, cache); got != want {
		t.Errorf("stamp is %q, want %q", got, want)
	}
	for _, id := range []string{"done", "todo"} {
		if _, err := secure.DecryptAge(ciphertexts[id], newID); err != nil {
			t.Errorf("ciphertext for %q was not handed back to the rest of the run: %v", id, err)
		}
	}
}

// A secret whose file comes from another flake belongs to whoever maintains
// that flake. It must not block a recipient change here, and it must not go
// unmentioned either: the recipient just added cannot read it.
func TestRefreshRecipientsReportsSecretsItDoesNotOwn(t *testing.T) {
	dir, cache := t.TempDir(), t.TempDir()
	id, extraID := x25519(t), x25519(t)

	ownPath, ownCT := writeSecret(t, dir, "own.age", "payload", id.Recipient())
	writeStampFile(t, cache, (stamp{identity: id.Recipient().String()}).String())

	profiles := []*profile.Profile{{Secrets: map[string]profile.Secret{
		"own":    {File: ownPath, SourcePath: ownPath},
		"shared": {File: "/nix/store/xxxx-other-flake/shared.age"},
	}}}
	ciphertexts := map[string][]byte{"own": ownCT}

	// Same identity, one added recipient: a change that needs no --old-identity.
	m := &manifest.Manifest{Cache: cache, ExtraRecipients: []string{extraID.Recipient().String()}}
	foreign, err := refreshRecipients(m, id, "", profiles, ciphertexts)
	if err != nil {
		t.Fatalf("a secret owned elsewhere blocked the recipient change: %v", err)
	}

	// The one it does own reaches the new recipient.
	if got := decryptFile(t, ownPath, extraID); got != "payload" {
		t.Errorf("own.age is %q to the added recipient, want %q", got, "payload")
	}

	if len(foreign) != 1 || !strings.Contains(foreign[0], "shared") {
		t.Errorf("secrets owned elsewhere were not reported: %v", foreign)
	}

	want := (stamp{identity: id.Recipient().String(), extra: []string{extraID.Recipient().String()}}).String()
	if got := readStampFile(t, cache); got != want {
		t.Errorf("stamp is %q, want %q", got, want)
	}
}

// `kix.hostPubkey = ./secrets/host.pub` hands the file's contents straight to
// the parser, and a file ends in a newline. agessh accepts it; age's own
// parser used to reject it, so an age host key failed where an SSH one worked.
func TestParseRecipientToleratesTheNewlineAFileEndsWith(t *testing.T) {
	for _, key := range []string{
		"age1kqn3nznrh0hmmkrvszcxzc2k8mlc94efqnm803axk4nt8p4wjv9szlzu2x",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8x0GNwFpNmVDLBHVJ5tQnFAF7mV8vNBOZ0aQKmm4mm root@host",
	} {
		if _, err := parseRecipient(key+"\n", nil); err != nil {
			t.Errorf("newline-terminated recipient rejected: %v", err)
		}
	}
}

// A PQ identity is one parseIdentity accepts, so it must not fall through to
// the extra recipients alone.
func TestIdentityRecipientHybrid(t *testing.T) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	r, name, err := identityRecipient(id)
	if err != nil {
		t.Fatalf("hybrid identity rejected: %v", err)
	}
	if r == nil {
		t.Error("no recipient returned")
	}
	if want := id.Recipient().String(); name != want {
		t.Errorf("got %q, want %q", name, want)
	}
}

func TestIdentityRecipientRejectsUnknown(t *testing.T) {
	if _, _, err := identityRecipient(&countingIdentity{}); err == nil {
		t.Error("an identity kix cannot derive a recipient from was accepted")
	}
}
