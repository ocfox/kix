// Package profile describes the per-host input kix receives from Nix.
//
// The shape here mirrors the `kix.profile` option in module/default.nix, which
// is an explicit projection rather than a dump of the whole option tree, so
// adding a NixOS option does not change the wire format.
package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

type Profile struct {
	Settings       Settings          `json:"settings"`
	Secrets        map[string]Secret `json:"secrets"`
	BeforeUserborn []string          `json:"beforeUserborn"`
}

type Settings struct {
	DecryptedDir        string    `json:"decryptedDir"`
	DecryptedDirForUser string    `json:"decryptedDirForUser"`
	DecryptedMountPoint string    `json:"decryptedMountPoint"`
	HostIdentifier      string    `json:"hostIdentifier"`
	HostPubkey          string    `json:"hostPubkey"`
	HostKeys            []HostKey `json:"hostKeys"`
	CacheInStore        string    `json:"cacheInStore"`
}

type HostKey struct {
	Path string `json:"path"`
}

type Secret struct {
	File  string `json:"file"`
	Group string `json:"group"`
	Mode  string `json:"mode"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
	Path  string `json:"path"`
}

func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile %q: %w", path, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile %q: %w", path, err)
	}
	return &p, nil
}

func LoadAll(paths []string) ([]*Profile, error) {
	profiles := make([]*Profile, 0, len(paths))
	for _, path := range paths {
		p, err := Load(path)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}
