package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

type Profile struct {
	Settings       Settings         `json:"settings"`
	Secrets        map[string]Secret `json:"secrets"`
	BeforeUserborn []string          `json:"beforeUserborn"`
}

type Settings struct {
	DecryptedDir          string    `json:"decryptedDir"`
	DecryptedDirForUser   string    `json:"decryptedDirForUser"`
	DecryptedMountPoint   string    `json:"decryptedMountPoint"`
	HostIdentifier        string    `json:"hostIdentifier"`
	HostPubkey            string    `json:"hostPubkey"`
	HostKeys              []HostKey `json:"hostKeys"`
	CacheInStore          string    `json:"cacheInStore"`
}

type HostKey struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Secret struct {
	ID               string    `json:"id"`
	File             string    `json:"file"`
	Group            string    `json:"group"`
	Mode             string    `json:"mode"`
	Name             string    `json:"name"`
	Owner            string    `json:"owner"`
	Path             string    `json:"path"`
	Insert           InsertSet `json:"insert"`
	CleanPlaceholder bool      `json:"cleanPlaceholder"`
}

type Insert struct {
	Order   uint32 `json:"order"`
	Content string `json:"content"`
}

type InsertSet struct {
	Entries map[string]Insert
}

func (is *InsertSet) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &is.Entries)
}

func (is InsertSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(is.Entries)
}

func LoadProfiles(paths []string) ([]*Profile, error) {
	var profiles []*Profile
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading profile %q: %w", p, err)
		}
		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			return nil, fmt.Errorf("parsing profile %q: %w", p, err)
		}
		profiles = append(profiles, &profile)
	}
	return profiles, nil
}
