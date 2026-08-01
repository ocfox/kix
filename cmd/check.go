package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ocfox/kix/profile"
	"github.com/ocfox/kix/secure"
)

var checkProfile string

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check secret status",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCheck(checkProfile)
	},
}

func init() {
	checkCmd.Flags().StringVarP(&checkProfile, "profile", "p", "", "profile of the host to check")
	checkCmd.MarkFlagRequired("profile")
}

func runCheck(profilePath string) error {
	p, err := profile.Load(profilePath)
	if err != nil {
		return err
	}

	var missing []string
	for id, s := range p.Secrets {
		original, err := os.ReadFile(s.File)
		if err != nil {
			return fmt.Errorf("reading secret file %s: %w", id, err)
		}
		path := filepath.Join(p.Settings.CacheInStore, secure.HashSecret(original, p.Settings.HostPubkey))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			missing = append(missing, path)
		}
	}

	if len(missing) > 0 {
		slog.Error("missing sealed secrets, run seal first")
		for _, m := range missing {
			slog.Error("missing", "path", m)
		}
		return fmt.Errorf("%d secret(s) not sealed", len(missing))
	}

	slog.Info("check complete")
	return nil
}
