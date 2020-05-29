package main

import (
	"crypto/sha1"
	"encoding/hex"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

// NewKeyGenerator returns a new key generator.
func NewKeyGenerator(secretKeyBaseHexString string) (*KeyGenerator, error) {
	secretKeyBase, err := hex.DecodeString(secretKeyBaseHexString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode secret key base")
	}
	return &KeyGenerator{secretKeyBase: secretKeyBase}, nil
}

// KeyGenerator derives a key from a given secret.
type KeyGenerator struct {
	secretKeyBase []byte
}

// Generate returns a key derived from the secret and salt.
func (g *KeyGenerator) Generate(salt string) []byte {
	return pbkdf2.Key(g.secretKeyBase, []byte(salt), 1000, 32, sha1.New)
}
