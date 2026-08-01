// Command age-plugin-kixtest is a fake age plugin standing in for a hardware
// token. The identity payload is the key itself, so two AGE-PLUGIN-KIXTEST-1...
// strings are two distinct tokens.
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/chacha20poly1305"
)

const stanzaType = "kixtest"

func main() {
	p, err := plugin.New("kixtest")
	if err != nil {
		log.Fatal(err)
	}

	keygen := flag.String("keygen", "", "print the identity for this hex key and exit")
	p.RegisterFlags(nil)
	flag.Parse()
	if *keygen != "" {
		data, err := hex.DecodeString(*keygen)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(plugin.EncodeIdentity("kixtest", data))
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		k, err := newKey(data)
		if err != nil {
			return nil, err
		}
		// A token with a PIN policy of "always": every unwrap asks again,
		// which is what makes the client's prompt count observable.
		k.pin, k.plugin = os.Getenv("KIXTEST_PIN"), p
		return k, nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) { return newKey(data) })
	os.Exit(p.Main())
}

type key struct {
	aead   cipher.AEAD
	pin    string
	plugin *plugin.Plugin
}

func newKey(data []byte) (*key, error) {
	k := make([]byte, chacha20poly1305.KeySize)
	copy(k, data)
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}
	return &key{aead: aead}, nil
}

func (k *key) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: stanzaType,
		Args: []string{base64.RawStdEncoding.EncodeToString(nonce)},
		Body: k.aead.Seal(nil, nonce, fileKey, nil),
	}}, nil
}

func (k *key) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if k.pin != "" {
		got, err := k.plugin.RequestValue("Enter PIN:", true)
		if err != nil {
			return nil, err
		}
		if got != k.pin {
			return nil, fmt.Errorf("wrong PIN")
		}
	}
	for _, s := range stanzas {
		if s.Type != stanzaType || len(s.Args) != 1 {
			continue
		}
		nonce, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil || len(nonce) != chacha20poly1305.NonceSize {
			continue
		}
		fileKey, err := k.aead.Open(nil, nonce, s.Body, nil)
		if err != nil {
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}
