package secure

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
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
			// Do not leave a plaintext behind under ownership nobody asked for.
			os.Remove(dst)
			return fmt.Errorf("chown %q: %w", dst, err)
		}
	}

	return nil
}

// setOwnerAndGroup fails rather than falling back to root. Falling back would
// silently widen or narrow who can read a secret: a file meant to be 0640
// alice:alice becomes 0640 root:root, so the service it was written for cannot
// read it, and a group that was supposed to be restricted becomes root's.
func setOwnerAndGroup(fd uintptr, ownerName, groupName string) error {
	uid, err := lookupUID(ownerName)
	if err != nil {
		return err
	}
	gid, err := lookupGID(groupName)
	if err != nil {
		return err
	}

	if err := unix.Fchown(int(fd), uid, gid); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

// root is resolved without consulting NSS. It is uid/gid 0 by definition, and
// the pre-userborn deployment runs before /etc/passwd exists, where every
// lookup fails -- including the one for root, which is the only owner such a
// secret is allowed to have.
func lookupUID(name string) (int, error) {
	if name == "" || name == "root" {
		return 0, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("looking up owner %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("owner %q has non-numeric uid %q: %w", name, u.Uid, err)
	}
	return uid, nil
}

func lookupGID(name string) (int, error) {
	if name == "" || name == "root" {
		return 0, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("looking up group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has non-numeric gid %q: %w", name, g.Gid, err)
	}
	return gid, nil
}
