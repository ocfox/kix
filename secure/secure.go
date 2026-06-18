package secure

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"slices"
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

func ExtractHashes(input string) []string {
	const (
		prefix  = "{{ "
		suffix  = " }}"
		hashLen = 64
		total   = len(prefix) + hashLen + len(suffix)
	)

	var result []string
	for i := 0; i <= len(input)-total; i++ {
		if input[i:i+len(prefix)] != prefix {
			continue
		}
		hashStart := i + len(prefix)
		hashEnd := hashStart + hashLen
		if input[hashEnd:hashEnd+len(suffix)] != suffix {
			continue
		}
		h := input[hashStart:hashEnd]
		if !isHex(h) {
			continue
		}
		result = append(result, h)
		i = hashEnd + len(suffix) - 1
	}
	return result
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func InsertContent(plaintext []byte, insSet map[string]profile.Insert, cleanAfterReplace bool) []byte {
	hashes := ExtractHashes(string(plaintext))
	if len(hashes) == 0 {
		return plaintext
	}

	entries := make([]profile.Insert, 0, len(insSet))
	for _, v := range insSet {
		entries = append(entries, v)
	}
	slices.SortFunc(entries, func(a, b profile.Insert) int {
		return cmp.Compare(a.Order, b.Order)
	})

	result := make([]byte, len(plaintext))
	copy(result, plaintext)

	replaced := make(map[string]bool)
	for _, ins := range entries {
		contentHash := hexHash(ins.Content)
		for _, h := range hashes {
			if h == contentHash {
				placeholder := "{{ " + h + " }}"
				result = bytes.ReplaceAll(result, []byte(placeholder), []byte(ins.Content))
				replaced[h] = true
				break
			}
		}
	}

	if cleanAfterReplace {
		for _, h := range hashes {
			if !replaced[h] {
				placeholder := "{{ " + h + " }}"
				result = bytes.ReplaceAll(result, []byte(placeholder), nil)
			}
		}
	}

	return result
}

func hexHash(content string) string {
	h, _ := blake2b.New256(nil)
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
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
