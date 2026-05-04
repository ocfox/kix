package secure

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"golang.org/x/crypto/blake2b"

	"github.com/ocfox/kix/owner"
	"github.com/ocfox/kix/parser"
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

func InsertContent(plaintext []byte, insSet profile.InsertSet, cleanAfterReplace bool) []byte {
	hashes := parser.ExtractHashes(string(plaintext))
	if len(hashes) == 0 {
		return plaintext
	}

	entries := make([]profile.Insert, 0, len(insSet.Entries))
	for _, v := range insSet.Entries {
		entries = append(entries, v)
	}
	sortInserts(entries)

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

func sortInserts(entries []profile.Insert) {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].Order < entries[i].Order {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
}

func DeployToFS(data []byte, secret *profile.Secret, dst string) error {
	perm, err := parser.ParsePermissions(secret.Mode)
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
		if err := owner.SetOwnerAndGroup(f.Fd(), secret.Owner, secret.Group); err != nil {
			return fmt.Errorf("chown %q: %w", dst, err)
		}
	}

	return nil
}
