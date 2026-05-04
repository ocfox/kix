package secure

import (
	"bytes"
	"testing"

	"filippo.io/age"

	"github.com/ocfox/kix/profile"
)

const helloWorld = "Hello, kix!"

func TestEncryptDecryptX25519(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptAge([]byte(helloWorld), a.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := DecryptAge(encrypted, a)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != helloWorld {
		t.Errorf("got %q, want %q", plaintext, helloWorld)
	}
}

func TestHashSecret(t *testing.T) {
	hash1 := HashSecret([]byte("hello"), "recipient-a")
	hash2 := HashSecret([]byte("hello"), "recipient-a")
	hash3 := HashSecret([]byte("hello"), "recipient-b")

	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("different recipient should produce different hash")
	}
	if len(hash1) != 64 {
		t.Errorf("hash len = %d, want 64", len(hash1))
	}
}

func TestDecryptAge_roundTrip(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("round-trip test data")
	encrypted, err := EncryptAge(want, a.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptAge(encrypted, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecryptAge_wrongIdentity(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptAge([]byte(helloWorld), a.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptAge(encrypted, b)
	if err == nil {
		t.Fatal("expected error with wrong identity")
	}
}

func TestEncryptAge_multiRecipient(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptAge([]byte(helloWorld), a.Recipient(), b.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptAge(encrypted, b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != helloWorld {
		t.Errorf("got %q, want %q", got, helloWorld)
	}

	got, err = DecryptAge(encrypted, a)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != helloWorld {
		t.Errorf("got %q, want %q", got, helloWorld)
	}
}

func TestInsertContent_noPlaceholder(t *testing.T) {
	input := []byte("no placeholder here")
	result := InsertContent(input, profile.InsertSet{}, false)
	if string(result) != string(input) {
		t.Errorf("no placeholder should return unchanged: got %q", result)
	}
}
