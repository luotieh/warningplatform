package nodeenroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const envelopeAlgo = "RSA-OAEP-SHA256+AES-256-GCM"

const envelopeVersion = 1

// CredentialEnvelope is produced by the master when enrollment contains an RSA public key.
// Only the node holding the matching private key can recover the embedded credentials JSON.
type CredentialEnvelope struct {
	V     int    `json:"v"`
	EK    string `json:"ek"`    // base64: RSA-OAEP-SHA256 encrypted AES-256 key
	Nonce string `json:"nonce"` // base64: AES-GCM nonce
	CT    string `json:"ct"`    // base64: AES-GCM ciphertext + tag
	Algo  string `json:"algo"`
}

// EncryptCredentialsJSON encrypts plaintext (typically JSON) for the given RSA public key.
func EncryptCredentialsJSON(pub *rsa.PublicKey, plaintext []byte) (*CredentialEnvelope, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt: %w", err)
	}
	return &CredentialEnvelope{
		V:     envelopeVersion,
		EK:    base64.StdEncoding.EncodeToString(ek),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
		Algo:  envelopeAlgo,
	}, nil
}

// ParseRSAPublicKeyFromPEM parses a PKIX PEM public key (RSA).
func ParseRSAPublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM is not an RSA public key")
	}
	return pub, nil
}

// ParseRSAPrivateKeyFromPEM parses PKCS1 or PKCS8 PEM private key (RSA).
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM is not an RSA private key")
	}
	return priv, nil
}

// DecryptCredentialEnvelope decrypts an envelope using the node's RSA private key.
func DecryptCredentialEnvelope(priv *rsa.PrivateKey, env *CredentialEnvelope) ([]byte, error) {
	if priv == nil || env == nil {
		return nil, fmt.Errorf("missing key or envelope")
	}
	if env.Algo != "" && env.Algo != envelopeAlgo {
		return nil, fmt.Errorf("unsupported envelope algo %q", env.Algo)
	}
	ek, err := base64.StdEncoding.DecodeString(env.EK)
	if err != nil {
		return nil, fmt.Errorf("ek base64: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce base64: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("ct base64: %w", err)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ek, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	return plain, nil
}
