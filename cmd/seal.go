package cmd

import (
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

var sealManifest string

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Re-encrypt secrets for each host",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSeal(sealManifest)
	},
}

func init() {
	sealCmd.Flags().StringVarP(&sealManifest, "manifest", "m", "", "manifest describing identity, cache and nodes")
	sealCmd.MarkFlagRequired("manifest")
}

func runSeal(manifestPath string) error {
	slog.Info("sealing...")

	m, err := manifest.Load(manifestPath)
	if err != nil {
		return err
	}

	idents, err := parseIdentityFile(m.Identity, terminalUI())
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}
	masterID := idents[0]

	allProfiles, err := profile.LoadAll(m.Profiles)
	if err != nil {
		return err
	}

	// Read all original encrypted secret files
	ciphertexts := make(map[string][]byte)
	for _, p := range allProfiles {
		for id, s := range p.Secrets {
			data, err := os.ReadFile(s.File)
			if err != nil {
				return fmt.Errorf("reading secret %q (%s): %w", id, s.File, err)
			}
			ciphertexts[id] = data
		}
	}

	// Build plan: hostID -> {secretID -> destPath}
	type hostPlan = map[string]string
	plan := make(map[string]hostPlan)
	for _, p := range allProfiles {
		hostID := p.Settings.HostIdentifier
		if plan[hostID] == nil {
			plan[hostID] = make(hostPlan)
		}
		for id := range p.Secrets {
			hash := secure.HashSecret(ciphertexts[id], p.Settings.HostPubkey)
			plan[hostID][id] = filepath.Join(m.Cache, hostID, hash)
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
		hostDir := filepath.Join(m.Cache, p.Settings.HostIdentifier)
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
				os.Remove(path)
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
		hostPubkeys[p.Settings.HostIdentifier] = p.Settings.HostPubkey
	}

	var (
		errs []error
		mu   sync.Mutex
		wg   sync.WaitGroup
	)

	for hostID, secs := range missing {
		recip, err := parseRecipient(hostPubkeys[hostID], nil)
		if err != nil {
			return fmt.Errorf("parsing host %q recipient: %w", hostID, err)
		}

		wg.Add(1)
		go func(hostID string, secs hostPlan, recip age.Recipient) {
			defer wg.Done()
			for id, dstPath := range secs {
				plaintext, err := secure.DecryptAge(ciphertexts[id], masterID)
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("decrypt %s: %w", id, err))
					mu.Unlock()
					return
				}
				encrypted, err := secure.EncryptAge(plaintext, recip)
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("encrypt %s for %s: %w", id, hostID, err))
					mu.Unlock()
					return
				}
				if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("mkdir for %s: %w", id, err))
					mu.Unlock()
					return
				}
				if err := os.WriteFile(dstPath, encrypted, 0o644); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("write %s: %w", dstPath, err))
					mu.Unlock()
					return
				}
				slog.Info("sealed", "secret", id, "host", hostID)
			}
		}(hostID, secs, recip)
	}

	wg.Wait()

	for _, e := range errs {
		slog.Error("seal error", "error", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("seal completed with %d error(s)", len(errs))
	}

	slog.Info("seal complete")
	return nil
}
