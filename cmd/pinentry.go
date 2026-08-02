package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// askPassphrase reads one secret, preferring pinentry so that graphical and
// keyring-backed prompts work, and falling back to the terminal.
//
// There is deliberately no setting for which pinentry to use: swapping it is
// done by putting one earlier on PATH, the same mechanism distribution
// alternatives and the usual wrapper scripts already rely on.
func askPassphrase(desc, prompt string) ([]byte, error) {
	if prog, ok := lookPinentry(); ok {
		return askPinentry(prog, desc, prompt)
	}
	return readSecretFromTTY(desc, prompt)
}

func lookPinentry() (string, bool) {
	path, err := exec.LookPath("pinentry")
	if err != nil {
		return "", false
	}
	return path, true
}

// readSecretFromTTY reads from the terminal directly, so it still works when
// stdin and stdout are redirected.
func readSecretFromTTY(desc, prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no pinentry on PATH and no terminal to prompt on: %w", err)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "%s\n%s ", desc, prompt)
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return secret, nil
}

// askPinentry drives prog over the Assuan protocol to read one secret.
func askPinentry(prog, desc, prompt string) ([]byte, error) {
	cmd := exec.Command(prog)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", prog, err)
	}
	defer cmd.Wait()
	defer stdin.Close()

	c := &assuan{in: bufio.NewReader(stdout), out: stdin}
	if _, err := c.read(); err != nil { // greeting
		return nil, err
	}
	// Without these a curses pinentry has no terminal to draw on and a
	// graphical one has no display to open. Implementations differ in which
	// they accept, though, and a refused option is not worth failing over.
	for _, opt := range terminalOptions() {
		if err := c.optional("OPTION " + opt); err != nil {
			return nil, err
		}
	}
	if err := c.command("SETDESC " + percentEncode(desc)); err != nil {
		return nil, err
	}
	if err := c.command("SETPROMPT " + percentEncode(prompt)); err != nil {
		return nil, err
	}

	if err := c.send("GETPIN"); err != nil {
		return nil, err
	}
	var pin []byte
	for {
		line, err := c.read()
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasPrefix(line, "D "):
			// Appended, not assigned: Assuan caps a line at around a kilobyte
			// and splits anything longer across several data lines, and taking
			// only the last one would hand back a passphrase that is wrong
			// without looking wrong.
			pin = append(pin, percentDecode(line[2:])...)
		case line == "OK" || strings.HasPrefix(line, "OK "):
			c.command("BYE")
			return pin, nil
		case strings.HasPrefix(line, "ERR "):
			return nil, assuanError(line)
		}
	}
}

func terminalOptions() []string {
	var opts []string
	tty := os.Getenv("GPG_TTY")
	if tty == "" {
		tty = "/dev/tty"
	}
	opts = append(opts, "ttyname="+tty)
	if term := os.Getenv("TERM"); term != "" {
		opts = append(opts, "ttytype="+term)
	}
	lc := os.Getenv("LC_CTYPE")
	if lc == "" {
		lc = os.Getenv("LANG")
	}
	if lc != "" {
		opts = append(opts, "lc-ctype="+lc)
	}
	// Only DISPLAY: there is no wayland_display option, and a graphical
	// pinentry on Wayland finds its own way to the compositor.
	if d := os.Getenv("DISPLAY"); d != "" {
		opts = append(opts, "display="+d)
	}
	return opts
}

type assuan struct {
	in  *bufio.Reader
	out io.Writer
}

func (c *assuan) send(line string) error {
	_, err := fmt.Fprintf(c.out, "%s\n", line)
	return err
}

// read returns the next line that carries meaning, skipping the status and
// comment lines pinentry emits as it works.
func (c *assuan) read() (string, error) {
	for {
		line, err := c.in.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading from pinentry: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "S ") || strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		return line, nil
	}
}

// command sends a line and waits for its acknowledgement.
func (c *assuan) command(line string) error {
	if err := c.send(line); err != nil {
		return err
	}
	resp, err := c.read()
	if err != nil {
		return err
	}
	if strings.HasPrefix(resp, "ERR ") {
		return assuanError(resp)
	}
	return nil
}

// assuanError turns "ERR <code> <description>" into just the description; the
// numeric code means nothing to the person reading the message.
// optional sends a line whose rejection does not matter, and fails only if the
// conversation itself breaks down.
func (c *assuan) optional(line string) error {
	if err := c.send(line); err != nil {
		return err
	}
	_, err := c.read()
	return err
}

func assuanError(line string) error {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "ERR "))
	if code, desc, ok := strings.Cut(rest, " "); ok {
		if _, err := strconv.Atoi(code); err == nil {
			rest = desc
		}
	}
	if rest = strings.TrimSpace(rest); rest != "" {
		return errors.New("pinentry: " + rest)
	}
	return errors.New("pinentry failed")
}

func percentEncode(s string) string {
	r := strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D")
	return r.Replace(s)
}

func percentDecode(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hexByte(s[i+1], s[i+2]); err == nil {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("not a hex digit")
}
