package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ocfox/kix/manifest"
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
	return refreshRecipients(&manifest.Manifest{Cache: cache}, id, "", nil, nil)
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
