package nodeenroll

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnrollmentKeyPath returns the private key path paired with an enrollment JSON path.
func EnrollmentKeyPath(jsonPath string) string {
	ext := filepath.Ext(jsonPath)
	if ext == "" {
		return jsonPath + ".key"
	}
	return strings.TrimSuffix(jsonPath, ext) + ".key"
}

// WriteEnrollmentBundle writes node-enrollment.json and a sibling .key file (0600) with RSA private key,
// and embeds the PKIX public key PEM in the JSON (safe to upload to the master).
func WriteEnrollmentBundle(outJSONPath string) error {
	f, err := BuildEnrollmentFile()
	if err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	f.PublicKeyPEM = string(pubPEM)

	keyPath := EnrollmentKeyPath(outJSONPath)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key %s: %w", keyPath, err)
	}
	b, err := MarshalIndentPretty(f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outJSONPath, b, 0o644); err != nil {
		return fmt.Errorf("write enrollment %s: %w", outJSONPath, err)
	}
	return nil
}
