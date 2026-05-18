// Package nodeauth hashes and verifies per-node secrets for node-api (X-Agent-Secret).
package nodeauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 10

// GeneratePlainSecret returns a 64-character hex string (32 random bytes).
func GeneratePlainSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashSecret returns a bcrypt hash suitable for storing on model.Node.AgentSecretHash.
func HashSecret(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("empty agent secret")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifySecret compares plaintext against a bcrypt hash.
func VerifySecret(plain, hash string) bool {
	if plain == "" || hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
