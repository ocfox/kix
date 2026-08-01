package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// writeFile puts contents in a temp file and returns its path.
func writeFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// passphraseIdentityFile writes an identity file encrypted under passphrase,
// the way `age -p` produces one, and returns its path with the identity inside.
func passphraseIdentityFile(t *testing.T, passphrase string) (path string, inner *age.X25519Identity) {
	t.Helper()
	inner, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatalf("NewScryptRecipient: %v", err)
	}
	r.SetWorkFactor(10) // keep the test fast

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := io.WriteString(w, inner.String()+"\n"); err != nil {
		t.Fatalf("writing identity: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	return writeFile(t, "id.age", buf.Bytes()), inner
}

// encryptedSSHKeyFile writes a passphrase-protected ed25519 key and returns it.
func encryptedSSHKeyFile(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return writeFile(t, "id_ed25519", pem.EncodeToMemory(block))
}

// asking returns a passphrase source that hands back answer and counts calls.
func asking(answer string, calls *int) passphraseFunc {
	return func(desc, prompt string) ([]byte, error) {
		*calls++
		return []byte(answer), nil
	}
}

func TestParseIdentityFileUnlocksAPassphraseIdentityFile(t *testing.T) {
	path, inner := passphraseIdentityFile(t, "hunter2")
	var calls int

	ids, err := parseIdentityFile(path, terminalUI(), asking("hunter2", &calls))
	if err != nil {
		t.Fatalf("parseIdentityFile: %v", err)
	}

	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	got, ok := ids[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("got identity of type %T, want *age.X25519Identity", ids[0])
	}
	if got.String() != inner.String() {
		t.Error("unlocked the wrong identity")
	}
	if calls != 1 {
		t.Errorf("asked for the passphrase %d times, want 1", calls)
	}
}

func TestParseIdentityFileReportsAWrongPassphrase(t *testing.T) {
	path, _ := passphraseIdentityFile(t, "hunter2")
	var calls int

	_, err := parseIdentityFile(path, terminalUI(), asking("wrong", &calls))
	if err == nil {
		t.Fatal("parseIdentityFile accepted a wrong passphrase")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error %q does not mention the passphrase", err)
	}
}

func TestParseIdentityFileAcceptsAnEncryptedSSHKey(t *testing.T) {
	path := encryptedSSHKeyFile(t, "hunter2")
	var calls int

	ids, err := parseIdentityFile(path, terminalUI(), asking("hunter2", &calls))
	if err != nil {
		t.Fatalf("parseIdentityFile: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}
