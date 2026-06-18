package secure

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"

	"github.com/ocfox/kix/profile"
)

func HashSecret(content []byte, hostRecipient string) string {
	h, _ := blake2b.New256(nil)
	h.Write(content)
	h.Write([]byte(hostRecipient))
	return hex.EncodeToString(h.Sum(nil))
}

func DecryptAge(encrypted []byte, idents ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(encrypted), idents...)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return io.ReadAll(r)
}

func EncryptAge(plaintext []byte, recips ...age.Recipient) ([]byte, error) {
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recips...)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close: %w", err)
	}
	return buf.Bytes(), nil
}

func ParsePermissions(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0")
	mode, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse permissions %q: %w", s, err)
	}
	return uint32(mode), nil
}

func DeployToFS(data []byte, secret *profile.Secret, dst string) error {
	perm, err := ParsePermissions(secret.Mode)
	if err != nil {
		return fmt.Errorf("parse mode %q: %w", secret.Mode, err)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(perm))
	if err != nil {
		return fmt.Errorf("creating %q: %w", dst, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing %q: %w", dst, err)
	}
	if err := f.Chmod(os.FileMode(perm)); err != nil {
		return fmt.Errorf("chmod %q: %w", dst, err)
	}

	if secret.Owner != "" || secret.Group != "" {
		if err := setOwnerAndGroup(f.Fd(), secret.Owner, secret.Group); err != nil {
			return fmt.Errorf("chown %q: %w", dst, err)
		}
	}

	return nil
}

func setOwnerAndGroup(fd uintptr, ownerName, groupName string) error {
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
