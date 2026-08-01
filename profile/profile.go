// Package profile describes the per-host input kix receives from Nix. The
// shape mirrors the `kix.profile` option in module/default.nix.
package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

type Profile struct {
	HostName     string    `json:"hostName"`
	HostPubkey   string    `json:"hostPubkey"`
	HostKeys     []HostKey `json:"hostKeys"`
	CacheInStore string    `json:"cacheInStore"`

	Dir        string `json:"dir"`
	DirForUser string `json:"dirForUser"`
	MountPoint string `json:"mountPoint"`

	Secrets map[string]Secret `json:"secrets"`
}

type HostKey struct {
	Path string `json:"path"`
}

type Secret struct {
	File           string `json:"file"`
	Group          string `json:"group"`
	Mode           string `json:"mode"`
	Name           string `json:"name"`
	Owner          string `json:"owner"`
	Path           string `json:"path"`
	SourcePath     string `json:"sourcePath"`
	BeforeUserborn bool   `json:"beforeUserborn"`
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
