package secure

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
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

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  uint32
		wantErr bool
	}{
		{"leading zero", "0700", 0o700, false},
		{"no leading zero", "700", 0o700, false},
		{"400", "400", 0o400, false},
		{"overflow", "33993", 0, true},
		{"many leading zeros", "0000111", 0o111, false},
		{"digit 8 in octal", "1000119", 0, true},
		// Go's FileMode carries setuid, setgid and sticky in its own bits,
		// not the octal ones, so these would be silently dropped on the way
		// to the file. Refusing them beats deploying a mode nobody asked for.
		{"setuid", "4755", 0, true},
		{"setgid", "2750", 0, true},
		{"sticky", "1777", 0, true},
		{"largest usable mode", "0777", 0o777, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePermissions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePermissions(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePermissions(%q): %v", tt.input, err)
			}
			if got != tt.expect {
				t.Errorf("ParsePermissions(%q) = %#o, want %#o", tt.input, got, tt.expect)
			}
		})
	}
}

func TestDeployToFS_unknownOwnerIsAnError(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "secret")
	secret := &profile.Secret{
		Mode:  "0400",
		Owner: "kix-test-user-that-does-not-exist",
	}

	err := DeployToFS([]byte("payload"), secret, dst)
	if err == nil {
		t.Fatal("expected an error, got nil: a failed lookup must not silently deploy as root")
	}

	// Assert on the cause, not just on "some error". Running as an ordinary
	// user the old fallback-to-uid-0 also errored, but from Fchown returning
	// EPERM; the point of the change is that the lookup failure itself is
	// surfaced instead of being turned into root ownership.
	var unknownUser user.UnknownUserError
	if !errors.As(err, &unknownUser) {
		t.Errorf("error was %v, want it to wrap user.UnknownUserError", err)
	}

	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("plaintext left behind at %s after a failed chown", dst)
	}
}

func TestDeployToFS_unknownGroupIsAnError(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "secret")
	secret := &profile.Secret{
		Mode:  "0400",
		Group: "kix-test-group-that-does-not-exist",
	}

	err := DeployToFS([]byte("payload"), secret, dst)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	var unknownGroup user.UnknownGroupError
	if !errors.As(err, &unknownGroup) {
		t.Errorf("error was %v, want it to wrap user.UnknownGroupError", err)
	}
}
