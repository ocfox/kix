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

// Two hardware tokens must not stamp alike. Going through Recipient().String()
// gave both the constant "<identity-based recipient>", which made rotating from
// one to the other compare equal and left the sources encrypted to the old one.
func TestIdentityStampDistinguishesPluginIdentities(t *testing.T) {
	a := identityStamp(pluginIdentity(t, "yubikey", []byte{1, 2, 3}))
	b := identityStamp(pluginIdentity(t, "yubikey", []byte{4, 5, 6}))

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
	first := identityStamp(pluginIdentity(t, "yubikey", []byte{1, 2, 3}))
	second := identityStamp(pluginIdentity(t, "yubikey", []byte{1, 2, 3}))

	if first != second {
		t.Errorf("same identity stamped %q then %q", first, second)
	}
}

// The stamp is committed, so it must carry a fingerprint rather than the
// identity itself.
func TestIdentityStampWithholdsTheIdentityEncoding(t *testing.T) {
	id := pluginIdentity(t, "yubikey", []byte{1, 2, 3})

	if got := identityStamp(id); strings.Contains(got, id.String()) {
		t.Errorf("stamp %q contains the identity encoding", got)
	}
}

func TestIdentityStampX25519UsesTheRecipient(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := identityStamp(id), id.Recipient().String(); got != want {
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

// The regression itself: swapping tokens has to be noticed and reported, not
// silently accepted.
func TestRefreshRecipientsDetectsPluginRotation(t *testing.T) {
	cache := t.TempDir()
	old := pluginIdentity(t, "yubikey", []byte{1, 2, 3})
	writeStampFile(t, cache, (stamp{identity: identityStamp(old)}).String())

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
	want := (stamp{identity: identityStamp(id)}).String()
	writeStampFile(t, cache, want)

	if err := refreshStamp(t, cache, id); err != nil {
		t.Fatalf("unchanged identity rejected: %v", err)
	}
	if got := readStampFile(t, cache); got != want {
		t.Errorf("stamp rewritten to %q, want %q", got, want)
	}
}

// A stamp written by an older kix holds the placeholder for whichever token the
// user has. It cannot say whether that token changed, so the upgrade must pass
// rather than accuse, and must leave a fingerprint behind so the next rotation
// is caught.
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
	want := (stamp{identity: identityStamp(id)}).String()
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Having upgraded, the next rotation is detected.
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
