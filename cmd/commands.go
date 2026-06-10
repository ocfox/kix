package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"

	"github.com/ocfox/kix/engine"
	"github.com/ocfox/kix/identity"
	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

func terminalUI() *plugin.ClientUI {
	return plugin.NewTerminalUI(
		func(format string, v ...any) { fmt.Printf(format, v...) },
		func(format string, v ...any) { fmt.Fprintf(os.Stderr, format, v...) },
	)
}

func runSeal(identityPath, cacheDir string) error {
	slog.Info("sealing...")

	idents, err := identity.ParseIdentityFile(identityPath, terminalUI())
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}
	if len(idents) == 0 {
		return fmt.Errorf("no identities found in %q", identityPath)
	}
	masterID := idents[0]

	allProfiles, err := profile.LoadProfiles(profiles)
	if err != nil {
		return err
	}

	if flakeRoot != "." {
		if _, err := os.Stat(filepath.Join(flakeRoot, "flake.nix")); err != nil {
			return fmt.Errorf("flake.nix not found in %q: %w", flakeRoot, err)
		}
	} else {
		if _, err := os.Stat("flake.nix"); err != nil {
			return fmt.Errorf("not running in flake root: %w", err)
		}
	}

	eng, err := engine.New(allProfiles, cacheDir)
	if err != nil {
		return err
	}

	slog.Info("cleaning outdated cache...")
	if err := eng.CleanOutdated(); err != nil {
		return err
	}

	slog.Info("sealing changed secrets...")
	if err := eng.Seal(masterID); err != nil {
		return err
	}

	slog.Info("seal complete")
	return nil
}

func runDeploy(early bool) error {
	if len(profiles) != 1 {
		return fmt.Errorf("deploy requires exactly one profile, got %d", len(profiles))
	}

	allProfiles, err := profile.LoadProfiles(profiles)
	if err != nil {
		return err
	}
	p := allProfiles[0]

	if early && len(p.BeforeUserborn) == 0 {
		slog.Info("nothing to deploy before userborn")
		return nil
	}
	if len(p.Secrets) == 0 {
		slog.Info("no secrets to deploy")
		return nil
	}

	hostKeys := getHostKeyIdentities(p)

	symlinkDst := p.Settings.DecryptedDir
	mountPoint := p.Settings.DecryptedMountPoint
	if early {
		symlinkDst = p.Settings.DecryptedDirForUser
	}

	if fi, err := os.Lstat(symlinkDst); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s exists and is not a symlink", symlinkDst)
		}
	}

	genDir, err := initGenerationDir(mountPoint, early)
	if err != nil {
		return err
	}

	eng, err := engine.New(allProfiles, p.Settings.CacheInStore)
	if err != nil {
		return err
	}

	var idents []age.Identity
	for _, hk := range hostKeys {
		idents = append(idents, hk)
	}

	plainMap, err := eng.DecryptToPlain(idents)
	if err != nil {
		return fmt.Errorf("decrypting secrets: %w", err)
	}

	for _, s := range p.Secrets {
		sec := s
		plaintext, ok := plainMap[sec.ID]
		if !ok {
			slog.Warn("secret not found in plaintext map", "secret", sec.ID)
			continue
		}

		if len(sec.Insert.Entries) > 0 || sec.CleanPlaceholder {
			plaintext = secure.InsertContent(plaintext, sec.Insert, sec.CleanPlaceholder)
		}

		defaultDst := filepath.Join(symlinkDst, sec.Name)
		var dst string
		if sec.Path == "" || sec.Path == defaultDst {
			dst = filepath.Join(genDir, sec.Name)
		} else {
			dst = sec.Path
		}

		if err := secure.DeployToFS(plaintext, &sec, dst); err != nil {
			slog.Error("deploy failed", "secret", sec.ID, "error", err)
			continue
		}
		slog.Info("deployed", "secret", sec.ID, "path", dst)
	}

	os.Remove(symlinkDst)
	if err := os.Symlink(genDir, symlinkDst); err != nil {
		return fmt.Errorf("creating symlink: %w", err)
	}

	slog.Info("deploy complete")
	return nil
}

func runEdit(file, identityPath string, recipients []string) error {
	ui := terminalUI()

	idents, err := identity.ParseIdentityFile(identityPath, ui)
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}
	if len(idents) == 0 {
		return fmt.Errorf("no identities found in %q", identityPath)
	}
	masterID := idents[0]

	var recips []age.Recipient
	masterRecip := getIdentityRecipient(masterID)
	if masterRecip != nil {
		recips = append(recips, masterRecip)
	}
	for _, r := range recipients {
		recip, err := identity.ParseRecipient(r, ui)
		if err != nil {
			return fmt.Errorf("parsing recipient %q: %w", r, err)
		}
		recips = append(recips, recip)
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vim"
		}

		cmd := exec.Command(editor, file)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("editor: %w", err)
		}

		plaintext, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading edited file: %w", err)
		}

		encrypted, err := secure.EncryptAge(plaintext, recips...)
		if err != nil {
			return fmt.Errorf("encrypting: %w", err)
		}

		if err := os.WriteFile(file, encrypted, 0o644); err != nil {
			return fmt.Errorf("writing encrypted file: %w", err)
		}

		slog.Info("created encrypted file", "path", file)
		return nil
	}

	encrypted, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	plaintext, err := secure.DecryptAge(encrypted, masterID)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	preHash := blake2bHash(plaintext)

	tmpFile, err := os.CreateTemp("", "kix-edit-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plaintext); err != nil {
		return fmt.Errorf("writing temp: %w", err)
	}
	tmpFile.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("reading edited: %w", err)
	}

	postHash := blake2bHash(edited)
	if postHash == preHash {
		slog.Info("file unchanged")
		return nil
	}

	encrypted, err = secure.EncryptAge(edited, recips...)
	if err != nil {
		return fmt.Errorf("re-encrypting: %w", err)
	}

	if err := os.WriteFile(file, encrypted, 0o644); err != nil {
		return fmt.Errorf("writing encrypted: %w", err)
	}

	slog.Info("edited and re-encrypted", "path", file)
	return nil
}

func runCheck() error {
	allProfiles, err := profile.LoadProfiles(profiles)
	if err != nil {
		return err
	}

	var missing []string
	for _, p := range allProfiles {
		eng, err := engine.New([]*profile.Profile{p}, p.Settings.CacheInStore)
		if err != nil {
			return err
		}
		plan := eng.PlanInstore(p.Settings.CacheInStore)
		for _, hm := range plan {
			for _, path := range hm {
				if _, err := os.Stat(path); os.IsNotExist(err) {
					missing = append(missing, path)
				}
			}
		}
	}

	if len(missing) > 0 {
		slog.Error("missing sealed secrets, run seal first")
		for _, m := range missing {
			slog.Error("  missing", "path", m)
		}
		return fmt.Errorf("%d secret(s) not sealed", len(missing))
	}

	slog.Info("check complete")
	return nil
}

func getHostKeyIdentities(p *profile.Profile) []age.Identity {
	var idents []age.Identity
	for _, hk := range p.Settings.HostKeys {
		keyData, err := os.ReadFile(hk.Path)
		if err != nil {
			slog.Warn("reading host key", "path", hk.Path, "error", err)
			continue
		}
		id, err := agessh.ParseIdentity(keyData)
		if err != nil {
			slog.Warn("parsing host key identity", "path", hk.Path, "error", err)
			continue
		}
		idents = append(idents, id)
	}
	return idents
}

func getIdentityRecipient(id age.Identity) age.Recipient {
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient()
	case *plugin.Identity:
		return id.Recipient()
	default:
		return nil
	}
}

func initGenerationDir(mountPoint string, early bool) (string, error) {
	target := "normal"
	if early {
		target = "early"
	}

	genBase := filepath.Join(mountPoint, target)

	if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
		if err := os.MkdirAll(mountPoint, 0o751); err != nil {
			return "", fmt.Errorf("creating mount point %s: %w", mountPoint, err)
		}
		if err := unix.Mount("ramfs", mountPoint, "ramfs", unix.MS_NOSUID, "mode=751"); err != nil {
			return "", fmt.Errorf("mounting ramfs at %s: %w", mountPoint, err)
		}
		if err := os.MkdirAll(genBase, 0o751); err != nil {
			return "", fmt.Errorf("creating %s: %w", genBase, err)
		}
		genDir := filepath.Join(genBase, "0")
		if err := os.MkdirAll(genDir, 0o751); err != nil {
			return "", fmt.Errorf("creating generation dir: %w", err)
		}
		return genDir, nil
	}

	if err := os.MkdirAll(genBase, 0o751); err != nil {
		return "", fmt.Errorf("creating %s: %w", genBase, err)
	}

	entries, _ := os.ReadDir(genBase)
	max := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var n int
		fmt.Sscanf(e.Name(), "%d", &n)
		if n >= max {
			max = n + 1
		}
	}

	genDir := filepath.Join(genBase, fmt.Sprintf("%d", max))
	if err := os.MkdirAll(genDir, 0o751); err != nil {
		return "", fmt.Errorf("creating generation dir: %w", err)
	}
	return genDir, nil
}

func blake2bHash(data []byte) string {
	h, _ := blake2b.New256(nil)
	h.Write(data)
	return string(h.Sum(nil))
}
