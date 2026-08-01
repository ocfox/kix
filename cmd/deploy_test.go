package cmd

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/ocfox/kix/profile"
)

// currentUserSecret describes a secret this test can actually write.
func currentUserSecret(t *testing.T, name string) profile.Secret {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatalf("LookupGroupId: %v", err)
	}
	return profile.Secret{Name: name, Mode: "0400", Owner: u.Username, Group: g.Name}
}

func TestActivateGenerationPointsTheSymlinkAtIt(t *testing.T) {
	base := t.TempDir()
	// The generations live under their own directory, as they do on a host:
	// pruning sweeps that directory, and the symlink must not be in it.
	genDir := filepath.Join(base, "generations", "1")
	if err := os.MkdirAll(genDir, 0o751); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(base, "current")

	secrets := map[string]profile.Secret{"one": currentUserSecret(t, "one")}
	plain := map[string][]byte{"one": []byte("payload")}

	if err := activateGeneration(genDir, link, secrets, plain); err != nil {
		t.Fatalf("activateGeneration: %v", err)
	}

	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != genDir {
		t.Errorf("symlink points at %q, want %q", target, genDir)
	}
	if _, err := os.Stat(filepath.Join(genDir, "one")); err != nil {
		t.Errorf("secret not deployed: %v", err)
	}
}

// A generation nothing points at still holds plaintext, and on ramfs it holds
// it until the machine reboots.
func TestActivateGenerationRemovesItselfWhenASecretFails(t *testing.T) {
	base := t.TempDir()
	// The generations live under their own directory, as they do on a host:
	// pruning sweeps that directory, and the symlink must not be in it.
	genDir := filepath.Join(base, "generations", "1")
	if err := os.MkdirAll(genDir, 0o751); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(base, "current")

	good := currentUserSecret(t, "good")
	bad := currentUserSecret(t, "bad")
	bad.Owner = "nobody-by-this-name"

	secrets := map[string]profile.Secret{"good": good, "bad": bad}
	plain := map[string][]byte{"good": []byte("payload"), "bad": []byte("payload")}

	if err := activateGeneration(genDir, link, secrets, plain); err == nil {
		t.Fatal("activateGeneration accepted a secret it could not write")
	}

	if _, err := os.Stat(genDir); !os.IsNotExist(err) {
		t.Errorf("the failed generation is still there: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("the symlink was pointed at a failed generation")
	}
}
