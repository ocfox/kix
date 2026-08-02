package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// scriptEditor stands in for $EDITOR, writing body into whatever file it is
// handed. The body goes through a file of its own so nothing has to be quoted
// into the script.
func scriptEditor(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()

	content := filepath.Join(dir, "content")
	if err := os.WriteFile(content, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	editor := filepath.Join(dir, "editor")
	script := "#!/bin/sh\ncat " + content + " > \"$1\"\n"
	if err := os.WriteFile(editor, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return editor
}

// secretsDir does not exist yet in a fresh repository, and edit used to notice
// only after the editor had closed -- by which point the plaintext existed
// nowhere but the temporary file it was about to remove.
func TestEditCreatesASecretUnderADirectoryThatDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	id := x25519(t)
	t.Setenv("EDITOR", scriptEditor(t, "the-secret\n"))

	target := filepath.Join(dir, "secrets", "new.age")
	if err := runEdit(target, "", writeIdentityFile(t, dir, id), nil); err != nil {
		t.Fatalf("editing into a directory that does not exist: %v", err)
	}

	if got := decryptFile(t, target, id); got != "the-secret\n" {
		t.Errorf("secret is %q, want %q", got, "the-secret\n")
	}
}

func TestWriteFileAtomicLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.age")

	if err := writeFileAtomic(path, []byte("ciphertext"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "secret.age" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want just secret.age", names)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("mode is %v, want 0644", got)
	}
}

// The file being replaced holds the only other copy of the secret, so a write
// that cannot finish has to leave it alone rather than truncate it first.
func TestWriteFileAtomicKeepsTheTargetWhenItCannotFinish(t *testing.T) {
	dir := t.TempDir()

	// A directory in the target's place: os.Rename refuses it, standing in for
	// the writes that fail for reasons a test cannot arrange.
	path := filepath.Join(dir, "secret.age")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	survivor := filepath.Join(path, "survivor")
	if err := os.WriteFile(survivor, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(path, []byte("ciphertext"), 0o644); err == nil {
		t.Fatal("a write that cannot complete reported success")
	}

	if _, err := os.Stat(survivor); err != nil {
		t.Errorf("the target was destroyed by a write that failed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("a temporary file was left behind: %d entries in %s", len(entries), dir)
	}
}
