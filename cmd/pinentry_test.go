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

// There is no wayland_display option; a real pinentry answers "Unknown
// option" and, before this was fixed, that killed the prompt.
func TestTerminalOptionsOnlySendsOptionsPinentryKnows(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	t.Setenv("DISPLAY", ":0")

	known := map[string]bool{"ttyname": true, "ttytype": true, "lc-ctype": true, "display": true}
	for _, opt := range terminalOptions() {
		name, _, _ := strings.Cut(opt, "=")
		if !known[name] {
			t.Errorf("terminalOptions sent unknown option %q", name)
		}
	}
}

// Implementations differ in which options they take, and none of them are
// worth failing the prompt over.
func TestAskPinentrySurvivesARejectedOption(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "pinentry")
	script := `#!/bin/sh
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
  case "$line" in
    OPTION*) printf 'ERR 83886254 Unknown option <Pinentry>\n' ;;
    GETPIN*) printf 'D hunter2\nOK\n' ;;
    BYE*) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake pinentry: %v", err)
	}

	got, err := askPinentry(prog, "unlocking id.txt", "Passphrase:")
	if err != nil {
		t.Fatalf("askPinentry: %v", err)
	}
	if string(got) != "hunter2" {
		t.Errorf("askPinentry returned %q, want %q", got, "hunter2")
	}
}

// A hardware token's PIN should reach the same prompt as everything else.
func TestTerminalUIAsksForPluginSecretsThroughPinentry(t *testing.T) {
	prog := fakePinentry(t, `printf 'D 123456\nOK\n'`)
	t.Setenv("PATH", filepath.Dir(prog))

	got, err := terminalUI().RequestValue("kixtest", "Enter PIN:", true)
	if err != nil {
		t.Fatalf("RequestValue: %v", err)
	}
	if got != "123456" {
		t.Errorf("RequestValue returned %q, want %q", got, "123456")
	}
}

// A token with a PIN policy of "always" is asked on every unwrap, and seal
// unwraps once per secret. The user must still be asked only once.
func TestTerminalUIAsksForAPluginSecretOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "pinentry")
	log := filepath.Join(dir, "prompts")
	script := `#!/bin/sh
echo asked >> ` + log + `
printf 'OK\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN*) printf 'D 123456\nOK\n' ;;
    BYE*) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake pinentry: %v", err)
	}
	t.Setenv("PATH", dir)

	ui := terminalUI()
	for i := range 3 {
		got, err := ui.RequestValue("kixtest", "Enter PIN:", true)
		if err != nil {
			t.Fatalf("RequestValue %d: %v", i, err)
		}
		if got != "123456" {
			t.Fatalf("RequestValue %d returned %q", i, got)
		}
	}

	prompts, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("reading prompts: %v", err)
	}
	if n := strings.Count(string(prompts), "asked"); n != 1 {
		t.Errorf("asked for the PIN %d times, want 1", n)
	}
}

// Two different questions are two different answers.
func TestTerminalUIDoesNotReuseAnAnswerForAnotherPrompt(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "pinentry")
	script := `#!/bin/sh
printf 'OK\n'
while IFS= read -r line; do
  case "$line" in
    SETPROMPT*) last="${line#SETPROMPT }"; printf 'OK\n' ;;
    GETPIN*) printf 'D answer-for-%s\nOK\n' "$last" ;;
    BYE*) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake pinentry: %v", err)
	}
	t.Setenv("PATH", dir)

	ui := terminalUI()
	first, err := ui.RequestValue("kixtest", "PIN:", true)
	if err != nil {
		t.Fatalf("RequestValue: %v", err)
	}
	second, err := ui.RequestValue("kixtest", "PUK:", true)
	if err != nil {
		t.Fatalf("RequestValue: %v", err)
	}
	if first == second {
		t.Errorf("both prompts returned %q", first)
	}
}

func TestAskPinentryReportsACancelledPrompt(t *testing.T) {
	prog := fakePinentry(t, `printf 'ERR 83886179 Operation cancelled\n'`)

	_, err := askPinentry(prog, "unlocking id.txt", "Passphrase:")
	if err == nil {
		t.Fatal("askPinentry ignored a cancelled prompt")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error %q does not say the prompt was cancelled", err)
	}
	// The Assuan error code means nothing to the person reading it.
	if strings.Contains(err.Error(), "83886179") {
		t.Errorf("error %q shows the raw Assuan code", err)
	}
}

// pinentry percent-escapes the secret it hands back.
func TestAskPinentryDecodesTheSecret(t *testing.T) {
	prog := fakePinentry(t, `printf 'D 100%%25%%0Asure\nOK\n'`)

	got, err := askPinentry(prog, "unlocking id.txt", "Passphrase:")
	if err != nil {
		t.Fatalf("askPinentry: %v", err)
	}
	if string(got) != "100%\nsure" {
		t.Errorf("askPinentry returned %q, want %q", got, "100%\nsure")
	}
}
