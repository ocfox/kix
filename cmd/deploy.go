package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

var (
	deployEarly   bool
	deployProfile string
)

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Decrypt and deploy secrets",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDeploy(deployProfile, deployEarly)
	},
}

func init() {
	deployCmd.Flags().StringVarP(&deployProfile, "profile", "p", "", "profile of the host to deploy")
	deployCmd.Flags().BoolVarP(&deployEarly, "early", "e", false, "deploy before users init")
	deployCmd.MarkFlagRequired("profile")
}

func runDeploy(profilePath string, earlyMode bool) error {
	p, err := profile.Load(profilePath)
	if err != nil {
		return err
	}

	// Each run owns exactly one of the two sets. Deploying all of them in both
	// runs would, in the early run, try to write the ordinary secrets into a
	// directory that the later run has not created yet.
	secrets := make(map[string]profile.Secret)
	for id, s := range p.Secrets {
		if s.BeforeUserborn == earlyMode {
			secrets[id] = s
		}
	}
	if len(secrets) == 0 {
		slog.Info("no secrets to deploy", "early", earlyMode)
		return nil
	}

	idents := hostKeyIdentities(p)

	symlinkDst := p.Dir
	if earlyMode {
		symlinkDst = p.DirForUser
	}

	if fi, err := os.Lstat(symlinkDst); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%q exists and is not a symlink", symlinkDst)
		}
	}

	genDir, err := nextGenDir(p.MountPoint, earlyMode)
	if err != nil {
		return err
	}

	// Decrypt secrets using host key
	plainMap := make(map[string][]byte)
	var verifiedIdent age.Identity

	for id, s := range secrets {
		// Original .age file gives us the hash that names the re-encrypted cache entry
		original, err := os.ReadFile(s.File)
		if err != nil {
			return fmt.Errorf("reading secret %q (%s): %w", id, s.File, err)
		}
		encPath := filepath.Join(p.CacheInStore, secure.HashSecret(original, p.HostPubkey))

		encrypted, err := os.ReadFile(encPath)
		if err != nil {
			return fmt.Errorf("reading cache entry for %q (%s): %w", id, encPath, err)
		}

		if verifiedIdent != nil {
			plaintext, err := secure.DecryptAge(encrypted, verifiedIdent)
			if err != nil {
				return fmt.Errorf("decrypting %q: %w", id, err)
			}
			plainMap[id] = plaintext
			continue
		}

		for _, ident := range idents {
			plaintext, err := secure.DecryptAge(encrypted, ident)
			if err == nil {
				verifiedIdent = ident
				plainMap[id] = plaintext
				break
			}
		}
		if plainMap[id] == nil {
			return fmt.Errorf(
				"no host key can decrypt secret %q: it was sealed to %q, "+
					"but none of this host's keys (%s) matches. "+
					"kix.hostPubkey is not the public half of a key in kix.hostKeys",
				id, strings.TrimSpace(p.HostPubkey), strings.Join(hostKeyPaths(p), ", "))
		}
	}

	if err := activateGeneration(genDir, symlinkDst, secrets, plainMap); err != nil {
		return err
	}

	slog.Info("deploy complete")
	return nil
}

// activateGeneration writes every secret into genDir and then points
// symlinkDst at it.
//
// Until the symlink is swapped nothing can reach genDir, so a generation that
// does not make it that far is discarded rather than left behind: it holds a
// full set of plaintext, and on ramfs that is pinned in RAM until the next
// successful deploy or a reboot.
func activateGeneration(genDir, symlinkDst string, secrets map[string]profile.Secret, plainMap map[string][]byte) error {
	discard := func() {
		if err := os.RemoveAll(genDir); err != nil {
			slog.Warn("removing the abandoned generation", "path", genDir, "error", err)
		}
	}

	var deployErrs []error
	for id, s := range secrets {
		dst := filepath.Join(genDir, s.Name)
		if err := secure.DeployToFS(plainMap[id], &s, dst); err != nil {
			slog.Error("deploy failed", "secret", id, "error", err)
			deployErrs = append(deployErrs, err)
			continue
		}
		slog.Info("deployed", "secret", id, "path", dst)
	}
	if len(deployErrs) > 0 {
		discard()
		return fmt.Errorf("deploy completed with %d error(s)", len(deployErrs))
	}

	if err := replaceSymlink(genDir, symlinkDst); err != nil {
		discard()
		return fmt.Errorf("pointing %q at %q: %w", symlinkDst, genDir, err)
	}

	pruneGenerations(filepath.Dir(genDir), genDir)
	return nil
}

// pruneGenerations removes every generation directory except keep.
//
// Each activation creates a new one holding a full set of plaintext secrets,
// and they live on ramfs, which is neither swapped nor reclaimed under memory
// pressure. Leaving them behind pins one copy of every secret in RAM per
// rebuild, forever.
//
// Called only after the symlink has been swapped, so the outgoing generation
// stays intact for as long as anything can still be pointed at it.
func pruneGenerations(genBase, keep string) {
	entries, err := os.ReadDir(genBase)
	if err != nil {
		slog.Warn("listing generations", "path", genBase, "error", err)
		return
	}
	for _, e := range entries {
		path := filepath.Join(genBase, e.Name())
		if path == keep {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("removing old generation", "path", path, "error", err)
		}
	}
}

// replaceSymlink points name at target without name ever being absent.
//
// Removing the old link and then creating the new one leaves a window in which
// name does not exist. That is invisible at boot, where consumers are ordered
// after kix-activate, but on `nixos-rebuild switch` the unit re-runs underneath
// services that are already running, and one reading its secret during the
// window gets ENOENT. Renaming over the old link is atomic, so a reader sees
// either the old generation or the new one.
func replaceSymlink(target, name string) error {
	tmp := name + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing %q: %w", tmp, err)
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func hostKeyPaths(p *profile.Profile) []string {
	paths := make([]string, 0, len(p.HostKeys))
	for _, hk := range p.HostKeys {
		paths = append(paths, hk.Path)
	}
	if len(paths) == 0 {
		return []string{"none configured"}
	}
	return paths
}

func hostKeyIdentities(p *profile.Profile) []age.Identity {
	var idents []age.Identity
	for _, hk := range p.HostKeys {
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

// ramfsMagic is RAMFS_MAGIC from linux/magic.h.
const ramfsMagic = 0x858458f6

// ensureRamfs makes mountPoint exist and be a ramfs mount.
//
// Testing whether the directory exists is not the same question: if it exists
// but nothing is mounted on it -- a failed mount that left the mkdir behind,
// or someone creating it by hand -- secrets land on the plain /run tmpfs
// instead. That matters because tmpfs pages can be swapped out and ramfs pages
// cannot, which is the whole reason for mounting anything here.
func ensureRamfs(mountPoint string) error {
	if err := os.MkdirAll(mountPoint, 0o751); err != nil {
		return fmt.Errorf("creating mount point %q: %w", mountPoint, err)
	}

	var st unix.Statfs_t
	if err := unix.Statfs(mountPoint, &st); err != nil {
		return fmt.Errorf("statfs %q: %w", mountPoint, err)
	}
	if st.Type == ramfsMagic {
		return nil
	}

	if err := unix.Mount("ramfs", mountPoint, "ramfs", unix.MS_NOSUID, "mode=751"); err != nil {
		return fmt.Errorf("mounting ramfs at %q: %w", mountPoint, err)
	}
	return nil
}

func nextGenDir(mountPoint string, early bool) (string, error) {
	target := "normal"
	if early {
		target = "early"
	}
	genBase := filepath.Join(mountPoint, target)

	if err := ensureRamfs(mountPoint); err != nil {
		return "", err
	}

	if err := os.MkdirAll(genBase, 0o751); err != nil {
		return "", fmt.Errorf("creating %q: %w", genBase, err)
	}

	entries, err := os.ReadDir(genBase)
	if err != nil {
		return "", fmt.Errorf("listing generations in %q: %w", genBase, err)
	}
	next := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if n >= next {
			next = n + 1
		}
	}

	genDir := filepath.Join(genBase, strconv.Itoa(next))
	if err := os.MkdirAll(genDir, 0o751); err != nil {
		return "", fmt.Errorf("creating generation dir: %w", err)
	}
	return genDir, nil
}
