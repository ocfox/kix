package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/ocfox/kix/manifest"
	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

var (
	sealManifest    string
	sealOldIdentity string
)

// hostPlan maps a secret id to the cache path it should be sealed into for one
// host.
type hostPlan = map[string]string

// sourceOf is where seal reads a secret from. The working tree copy, not the
// one in the flake source, so a secret just written by `edit` does not have to
// be committed before it can be sealed. Secrets pointed outside `secretsDir`
// have no working tree path and are read where they are.
func sourceOf(s profile.Secret) string {
	if s.SourcePath != "" {
		return s.SourcePath
	}
	return s.File
}

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Re-encrypt secrets for each host",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSeal(sealManifest, sealOldIdentity)
	},
}

func init() {
	sealCmd.Flags().StringVarP(&sealManifest, "manifest", "m", "", "manifest describing identity, cache and nodes")
	sealCmd.Flags().StringVar(&sealOldIdentity, "old-identity", "", "identity the source secrets are currently encrypted to, when rotating flake.kix.identity")
	sealCmd.MarkFlagRequired("manifest")
}

func runSeal(manifestPath, oldIdentityPath string) error {
	slog.Info("sealing...")

	m, err := manifest.Load(manifestPath)
	if err != nil {
		return err
	}

	masterID, err := parseIdentityFile(m.Identity, terminalUI(), askPassphrase)
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}

	allProfiles, err := profile.LoadAll(m.Profiles)
	if err != nil {
		return err
	}

	// Read all original encrypted secret files
	ciphertexts := make(map[string][]byte)
	for _, p := range allProfiles {
		for id, s := range p.Secrets {
			src := sourceOf(s)
			data, err := os.ReadFile(src)
			if os.IsNotExist(err) {
				return fmt.Errorf("secret %q is declared but %s does not exist:\n\n"+
					"    nix run .#kix-edit -- %s", id, src, src)
			}
			if err != nil {
				return fmt.Errorf("reading secret %q (%s): %w", id, src, err)
			}
			ciphertexts[id] = data
		}
	}

	foreign, err := refreshRecipients(m, masterID, oldIdentityPath, allProfiles, ciphertexts)
	if err != nil {
		return err
	}

	// Build plan: hostID -> {secretID -> destPath}
	plan := make(map[string]hostPlan)
	for _, p := range allProfiles {
		hostID := p.HostName
		if plan[hostID] == nil {
			plan[hostID] = make(hostPlan)
		}
		for id := range p.Secrets {
			plan[hostID][id] = filepath.Join(m.Cache, hostID,
				secure.CacheEntryName(id, ciphertexts[id], p.HostPubkey))
		}
	}

	// Remove cache entries no longer in plan
	slog.Info("cleaning outdated cache...")
	current := make(map[string]bool)
	for _, hm := range plan {
		for _, path := range hm {
			current[path] = true
		}
	}
	for _, p := range allProfiles {
		hostDir := filepath.Join(m.Cache, p.HostName)
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("reading cache dir %q: %w", hostDir, err)
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(hostDir, e.Name())
			if !current[path] {
				slog.Debug("removing outdated", "path", path)
				if err := os.Remove(path); err != nil {
					slog.Warn("removing outdated cache entry", "path", path, "error", err)
				}
			}
		}
	}

	// Seal only missing entries
	slog.Info("sealing changed secrets...")
	missing := make(map[string]hostPlan)
	for hostID, hm := range plan {
		for id, path := range hm {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if missing[hostID] == nil {
					missing[hostID] = make(hostPlan)
				}
				missing[hostID][id] = path
			}
		}
	}

	hostPubkeys := make(map[string]string)
	for _, p := range allProfiles {
		hostPubkeys[p.HostName] = p.HostPubkey
	}

	plaintexts, err := decryptOnce(ciphertexts, missing, masterID)
	if err != nil {
		return err
	}

	var (
		errs []error
		mu   sync.Mutex
		wg   sync.WaitGroup
	)

	// Encryption is pure computation over an already-decrypted plaintext, so
	// unlike the decryption above it is safe to run per host in parallel.
	for hostID, secs := range missing {
		recip, err := parseRecipient(hostPubkeys[hostID], nil)
		if err != nil {
			return fmt.Errorf("parsing host %q recipient: %w", hostID, err)
		}

		wg.Add(1)
		go func(hostID string, secs hostPlan, recip age.Recipient) {
			defer wg.Done()
			for id, dstPath := range secs {
				fail := func(err error) {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
				encrypted, err := secure.EncryptAge(plaintexts[id], recip)
				if err != nil {
					fail(fmt.Errorf("encrypting %q for host %q: %w", id, hostID, err))
					continue
				}
				if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
					fail(fmt.Errorf("creating cache dir for %q: %w", id, err))
					continue
				}
				if err := os.WriteFile(dstPath, encrypted, 0o644); err != nil {
					fail(fmt.Errorf("writing %q: %w", dstPath, err))
					continue
				}
				slog.Info("sealed", "secret", id, "host", hostID)
			}
		}(hostID, secs, recip)
	}

	wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	slog.Info("seal complete")
	// After the sealing, so it is what is left on screen rather than what
	// scrolled off it.
	reportForeign(foreign)
	return nil
}

// decryptOnce decrypts each distinct secret in the plan exactly once.
//
// This must not run concurrently and must not repeat work per host. A plugin
// identity (age-plugin-yubikey and friends) spawns a fresh plugin process on
// every Unwrap and shares a single unsynchronised *plugin.ClientUI, so running
// several at once means multiple processes contending for one hardware token
// and one terminal. Decrypting per (host, secret) pair rather than per secret
// also means a secret shared by N hosts costs N token interactions.
func decryptOnce(
	ciphertexts map[string][]byte,
	missing map[string]hostPlan,
	id age.Identity,
) (map[string][]byte, error) {
	plaintexts := make(map[string][]byte)
	for _, secs := range missing {
		for secretID := range secs {
			if _, done := plaintexts[secretID]; done {
				continue
			}
			plaintext, err := secure.DecryptAge(ciphertexts[secretID], id)
			if err != nil {
				return nil, fmt.Errorf("decrypting %q: %w", secretID, err)
			}
			plaintexts[secretID] = plaintext
		}
	}
	return plaintexts, nil
}
