package cmd

import (
	"testing"

	"filippo.io/age"

	"github.com/ocfox/kix/secure"
)

// countingIdentity records how many times age asks it to unwrap a file key,
// which for a plugin identity is one plugin process and one token interaction.
type countingIdentity struct {
	inner age.Identity
	calls int
}

func (c *countingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	c.calls++
	return c.inner.Unwrap(stanzas)
}

func TestDecryptOnce_sharedSecretDecryptedOnce(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("shared payload")
	ciphertext, err := secure.EncryptAge(want, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	// One secret used by three hosts: the old code decrypted it once per host.
	ciphertexts := map[string][]byte{"shared": ciphertext}
	missing := map[string]map[string]string{
		"hostA": {"shared": "/cache/hostA/x"},
		"hostB": {"shared": "/cache/hostB/x"},
		"hostC": {"shared": "/cache/hostC/x"},
	}

	counting := &countingIdentity{inner: id}
	plaintexts, err := decryptOnce(ciphertexts, missing, counting)
	if err != nil {
		t.Fatal(err)
	}

	if counting.calls != 1 {
		t.Errorf("unwrapped %d times, want 1", counting.calls)
	}
	if string(plaintexts["shared"]) != string(want) {
		t.Errorf("got %q, want %q", plaintexts["shared"], want)
	}
}

func TestDecryptOnce_distinctSecrets(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	ciphertexts := map[string][]byte{}
	for _, name := range []string{"a", "b"} {
		ct, err := secure.EncryptAge([]byte(name), id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		ciphertexts[name] = ct
	}

	missing := map[string]map[string]string{
		"hostA": {"a": "/cache/hostA/a", "b": "/cache/hostA/b"},
		"hostB": {"a": "/cache/hostB/a"},
	}

	counting := &countingIdentity{inner: id}
	plaintexts, err := decryptOnce(ciphertexts, missing, counting)
	if err != nil {
		t.Fatal(err)
	}

	if counting.calls != 2 {
		t.Errorf("unwrapped %d times, want 2 (one per distinct secret)", counting.calls)
	}
	if string(plaintexts["a"]) != "a" || string(plaintexts["b"]) != "b" {
		t.Errorf("wrong plaintexts: %q %q", plaintexts["a"], plaintexts["b"])
	}
}

func TestDecryptOnce_wrongIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := secure.EncryptAge([]byte("x"), other.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	_, err = decryptOnce(
		map[string][]byte{"s": ciphertext},
		map[string]map[string]string{"hostA": {"s": "/cache/hostA/s"}},
		id,
	)
	if err == nil {
		t.Fatal("expected an error when no identity can decrypt")
	}
}
