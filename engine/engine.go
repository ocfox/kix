package engine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"

	"github.com/ocfox/kix/identity"
	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

type Engine struct {
	profiles []*profile.Profile
	cacheDir string
	ctx      map[string][]byte
	plan     map[string][]*profile.Secret
}

func New(profiles []*profile.Profile, cacheDir string) (*Engine, error) {
	e := &Engine{
		profiles: profiles,
		cacheDir: cacheDir,
		ctx:      make(map[string][]byte),
		plan:     make(map[string][]*profile.Secret),
	}

	for _, p := range profiles {
		for _, s := range p.Secrets {
			sec := s
			data, err := os.ReadFile(sec.File)
			if err != nil {
				return nil, fmt.Errorf("reading secret %q (%s): %w", sec.ID, sec.File, err)
			}
			e.ctx[sec.ID] = data
		}

		hostID := p.Settings.HostIdentifier
		for _, s := range p.Secrets {
			sec := s
			e.plan[hostID] = append(e.plan[hostID], &sec)
		}
	}

	return e, nil
}

func (e *Engine) PlanRepo() map[string]map[string]string {
	out := make(map[string]map[string]string)

	for hostID, secs := range e.plan {
		hostPubkey := e.getHostPubkey(hostID)
		for _, s := range secs {
			ciphertext := e.ctx[s.ID]
			hash := secure.HashSecret(ciphertext, hostPubkey)
			path := filepath.Join(e.cacheDir, hostID, hash)
			if out[s.ID] == nil {
				out[s.ID] = make(map[string]string)
			}
			out[s.ID][hostID] = path
		}
	}
	return out
}

func (e *Engine) PlanInstore(cacheInStore string) map[string]map[string]string {
	out := make(map[string]map[string]string)

	for hostID, secs := range e.plan {
		hostPubkey := e.getHostPubkey(hostID)
		for _, s := range secs {
			ciphertext := e.ctx[s.ID]
			hash := secure.HashSecret(ciphertext, hostPubkey)
			path := filepath.Join(cacheInStore, hash)
			if out[s.ID] == nil {
				out[s.ID] = make(map[string]string)
			}
			out[s.ID][hostID] = path
		}
	}
	return out
}

func (e *Engine) CleanOutdated() error {
	plan := e.PlanRepo()
	current := make(map[string]bool)
	for _, hm := range plan {
		for _, p := range hm {
			current[p] = true
		}
	}

	for _, p := range e.profiles {
		hostDir := filepath.Join(e.cacheDir, p.Settings.HostIdentifier)
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("reading host cache dir %q: %w", hostDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(hostDir, entry.Name())
			if !current[fullPath] {
				slog.Debug("cleaning outdated cache", "path", fullPath)
				os.Remove(fullPath)
			}
		}
	}
	return nil
}

func (e *Engine) MissingOnly() map[string]map[string]string {
	plan := e.PlanRepo()
	missing := make(map[string]map[string]string)

	for id, hm := range plan {
		for hostID, path := range hm {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if missing[id] == nil {
					missing[id] = make(map[string]string)
				}
				missing[id][hostID] = path
			}
		}
	}
	return missing
}

func (e *Engine) Seal(masterID age.Identity) error {
	plan := e.MissingOnly()

	byHost := make(map[string]map[string]string)
	for id, hm := range plan {
		for hostID, path := range hm {
			if byHost[hostID] == nil {
				byHost[hostID] = make(map[string]string)
			}
			byHost[hostID][id] = path
		}
	}

	type result struct {
		host string
		err  error
	}

	var (
		results []result
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	for hostID, secs := range byHost {
		wg.Add(1)
		go func(hostID string, secs map[string]string) {
			defer wg.Done()

			hostPubkey := e.getHostPubkey(hostID)
			recip, err := identity.ParseRecipient(hostPubkey, nil)
			if err != nil {
				mu.Lock()
				results = append(results, result{host: hostID, err: fmt.Errorf("parse host %q recipient: %w", hostID, err)})
				mu.Unlock()
				return
			}

			for id, dstPath := range secs {
				plaintext, err := secure.DecryptAge(e.ctx[id], masterID)
				if err != nil {
					mu.Lock()
					results = append(results, result{host: hostID, err: fmt.Errorf("decrypt %s: %w", id, err)})
					mu.Unlock()
					return
				}

				encrypted, err := secure.EncryptAge(plaintext, recip)
				if err != nil {
					mu.Lock()
					results = append(results, result{host: hostID, err: fmt.Errorf("encrypt %s for %s: %w", id, hostID, err)})
					mu.Unlock()
					return
				}

				if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
					mu.Lock()
					results = append(results, result{host: hostID, err: fmt.Errorf("mkdir %s: %w", filepath.Dir(dstPath), err)})
					mu.Unlock()
					return
				}

				if err := os.WriteFile(dstPath, encrypted, 0o644); err != nil {
					mu.Lock()
					results = append(results, result{host: hostID, err: fmt.Errorf("write %s: %w", dstPath, err)})
					mu.Unlock()
					return
				}

				slog.Info("sealed", "secret", id, "host", hostID)
			}
		}(hostID, secs)
	}

	wg.Wait()

	for _, r := range results {
		slog.Error("seal error", "host", r.host, "error", r.err)
	}
	if len(results) > 0 {
		return fmt.Errorf("seal completed with %d error(s)", len(results))
	}
	return nil
}

func (e *Engine) DecryptToPlain(idents []age.Identity) (map[string][]byte, error) {
	plainMap := make(map[string][]byte)
	var verifiedIdx int
	foundKey := false

	for _, p := range e.profiles {
		for _, s := range p.Secrets {
			sec := s
			plan := e.PlanInstore(p.Settings.CacheInStore)
			hostPaths, ok := plan[sec.ID]
			if !ok {
				return nil, fmt.Errorf("secret %s not in plan", sec.ID)
			}

			var encPath string
			for _, v := range hostPaths {
				encPath = v
			}

			if encPath == "" {
				continue
			}

			encrypted, err := os.ReadFile(encPath)
			if err != nil {
				return nil, fmt.Errorf("reading cache for %s at %s: %w", sec.ID, encPath, err)
			}

			if foundKey {
				plaintext, err := secure.DecryptAge(encrypted, idents[verifiedIdx])
				if err != nil {
					return nil, fmt.Errorf("decrypting %s: %w", sec.ID, err)
				}
				plainMap[sec.ID] = plaintext
				continue
			}

			decrypted := false
			for idx, ident := range idents {
				plaintext, err := secure.DecryptAge(encrypted, ident)
				if err == nil {
					verifiedIdx = idx
					foundKey = true
					plainMap[sec.ID] = plaintext
					decrypted = true
					break
				}
			}
			if !decrypted {
				return nil, fmt.Errorf("no key can decrypt secret %s", sec.ID)
			}
		}
	}

	return plainMap, nil
}

func (e *Engine) getHostPubkey(hostID string) string {
	for _, p := range e.profiles {
		if p.Settings.HostIdentifier == hostID {
			return p.Settings.HostPubkey
		}
	}
	return ""
}
