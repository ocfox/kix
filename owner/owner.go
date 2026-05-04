package owner

import (
	"fmt"
	"log/slog"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

func SetOwnerAndGroup(fd uintptr, ownerName, groupName string) error {
	uid, gid := 0, 0

	if ownerName != "" {
		u, err := user.Lookup(ownerName)
		if err != nil {
			slog.Warn("owner lookup failed, falling back to root", "owner", ownerName, "error", err)
		} else {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}

	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			slog.Warn("group lookup failed, falling back to root", "group", groupName, "error", err)
		} else {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}

	if err := unix.Fchown(int(fd), uid, gid); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}
