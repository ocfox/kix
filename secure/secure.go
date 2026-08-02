// Package secure holds the cryptographic and filesystem primitives shared by
// the commands: age encryption and decryption, the cache naming hash, and
// writing a plaintext out with the ownership and mode a secret asks for.
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

// HashSecret identifies a source secret sealed to a given host.
//
// Both inputs matter: the same ciphertext sealed to two hosts must land in two
// entries, and a changed source must not reuse the old host's entry.
//
// The recipient is trimmed first. `kix.hostPubkey` is often a file read by Nix
// and so ends in a newline, and the same key written inline does not; without
// this the two spell the same host two ways and reseal everything.
func HashSecret(content []byte, hostRecipient string) string {
	h, _ := blake2b.New256(nil)
	h.Write(content)
	h.Write([]byte(strings.TrimSpace(hostRecipient)))
	return hex.EncodeToString(h.Sum(nil))
}

// hashHexLen is how long HashSecret's output is, which is what tells an entry
// name apart from a secret id that merely starts like one.
const hashHexLen = 2 * blake2b.Size256

// CacheEntryName is what a sealed secret is called inside a host's cache
// directory.
//
// Both halves earn their place. The hash makes a stale entry visible without
// decrypting it, which is how seal and check know the cache still matches the
// source. The id makes the entry findable by a deploy that has never seen the
// source: it holds no identity that could read the source anyway, and shipping
// it one only to compute a filename would put material encrypted to the admin
// identity on every host.
func CacheEntryName(id string, content []byte, hostRecipient string) string {
	return id + "-" + HashSecret(content, hostRecipient)
}

// FindCacheEntry picks the entry belonging to id out of a directory listing.
//
// Matching on the prefix alone would let a secret named "db" claim the entry
// of one named "db-backup", so the rest of the name has to look like a hash
// and nothing else.
func FindCacheEntry(names []string, id string) (string, error) {
	var found []string
	for _, name := range names {
		rest, ok := strings.CutPrefix(name, id+"-")
		if !ok || len(rest) != hashHexLen {
			continue
		}
		if _, err := hex.DecodeString(rest); err != nil {
			continue
		}
		found = append(found, name)
	}

	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("no sealed entry for secret %q", id)
	default:
		return "", fmt.Errorf("secret %q has %d sealed entries (%s); seal removes the outdated ones",
			id, len(found), strings.Join(found, ", "))
	}
}

// DecryptAge decrypts an age file with the first of idents that can read it.
func DecryptAge(encrypted []byte, idents ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(encrypted), idents...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return io.ReadAll(r)
}

// EncryptAge encrypts plaintext to every recipient in recips.
func EncryptAge(plaintext []byte, recips ...age.Recipient) ([]byte, error) {
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recips...)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing ciphertext: %w", err)
	}
	return buf.Bytes(), nil
}

// ParsePermissions reads an octal mode as written in Nix, with or without the
// leading zero, so both "0400" and "400" mean the same thing.
//
// Anything above 0777 is refused rather than accepted and dropped: setuid,
// setgid and sticky live in [os.FileMode]'s own bits, not in the octal ones,
// so a mode like "4755" would reach the file as plain 0755.
func ParsePermissions(s string) (uint32, error) {
	trimmed := strings.TrimPrefix(s, "0")
	mode, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing permissions %q: %w", s, err)
	}
	if mode > 0o777 {
		return 0, fmt.Errorf("permissions %q are above 0777: setuid, setgid and sticky are not supported", s)
	}
	return uint32(mode), nil
}

// DeployToFS writes a decrypted secret to dst with the mode, owner and group
// the secret declares. It removes dst rather than leaving a plaintext behind
// under ownership nobody asked for.
func DeployToFS(data []byte, secret *profile.Secret, dst string) error {
	perm, err := ParsePermissions(secret.Mode)
	if err != nil {
		return err
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
