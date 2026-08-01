package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePinentry writes a script speaking just enough Assuan to stand in for a
// real pinentry, and returns its path. body handles GETPIN.
func fakePinentry(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pinentry")
	script := `#!/bin/sh
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN*) ` + body + ` ;;
    BYE*) printf 'OK closing connection\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake pinentry: %v", err)
	}
	return path
}

// recordingPinentry is a fake that appends every command it receives to a file
// before answering, so a test can assert on the conversation.
func recordingPinentry(t *testing.T) (prog string, transcript func() string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pinentry")
	log := filepath.Join(dir, "transcript")
	script := `#!/bin/sh
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
  printf '%s\n' "$line" >> ` + log + `
  case "$line" in
    GETPIN*) printf 'D hunter2\nOK\n' ;;
    BYE*) printf 'OK closing connection\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake pinentry: %v", err)
	}
	return path, func() string {
		b, err := os.ReadFile(log)
		if err != nil {
			t.Fatalf("reading transcript: %v", err)
		}
		return string(b)
	}
}

func TestLookPinentryFindsPinentryOnPath(t *testing.T) {
	prog := fakePinentry(t, `printf 'D hunter2\nOK\n'`)
	t.Setenv("PATH", filepath.Dir(prog))

	got, ok := lookPinentry()
	if !ok {
		t.Fatal("lookPinentry did not find pinentry on PATH")
	}
	if got != prog {
		t.Errorf("lookPinentry found %q, want %q", got, prog)
	}
}

// Users swap pinentry by putting their own on PATH, so an empty PATH is the
// signal to fall back to the terminal rather than an error.
func TestLookPinentryReportsWhenThereIsNone(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if got, ok := lookPinentry(); ok {
		t.Errorf("lookPinentry found %q on an empty PATH", got)
	}
}

func TestAskPassphraseUsesPinentryFromPath(t *testing.T) {
	prog := fakePinentry(t, `printf 'D hunter2\nOK\n'`)
	t.Setenv("PATH", filepath.Dir(prog))

	got, err := askPassphrase("unlocking id.txt", "Passphrase:")
	if err != nil {
		t.Fatalf("askPassphrase: %v", err)
	}
	if string(got) != "hunter2" {
		t.Errorf("askPassphrase returned %q, want %q", got, "hunter2")
	}
}

// pinentry-curses cannot draw without being told which terminal to draw on.
func TestAskPinentryTellsPinentryWhichTerminalToUse(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	prog, transcript := recordingPinentry(t)

	if _, err := askPinentry(prog, "unlocking id.txt", "Passphrase:"); err != nil {
		t.Fatalf("askPinentry: %v", err)
	}

	got := transcript()
	if !strings.Contains(got, "OPTION ttyname=") {
		t.Errorf("no ttyname option in conversation:\n%s", got)
	}
	if !strings.Contains(got, "OPTION ttytype=xterm-256color") {
		t.Errorf("no ttytype option in conversation:\n%s", got)
	}
}

func TestAskPinentryReturnsThePassphrase(t *testing.T) {
	prog := fakePinentry(t, `printf 'D hunter2\nOK\n'`)

	got, err := askPinentry(prog, "unlocking id.txt", "Passphrase:")
	if err != nil {
		t.Fatalf("askPinentry: %v", err)
	}
	if string(got) != "hunter2" {
		t.Errorf("askPinentry returned %q, want %q", got, "hunter2")
	}
}
