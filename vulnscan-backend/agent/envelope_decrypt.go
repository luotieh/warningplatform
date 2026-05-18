package agent

import (
	"encoding/json"
	"fmt"
	"os"

	"vulnscan-backend/pkg/nodeenroll"
)

// DecryptCredentialEnvelopeToFile reads an envelope JSON (from the master) and RSA private key PEM,
// decrypts to plaintext credentials JSON (same shape as CredentialsFile) and writes outPath.
func DecryptCredentialEnvelopeToFile(envelopePath, privKeyPath, outPath string) error {
	eb, err := os.ReadFile(envelopePath)
	if err != nil {
		return fmt.Errorf("read envelope: %w", err)
	}
	var env nodeenroll.CredentialEnvelope
	if err := json.Unmarshal(eb, &env); err != nil {
		return fmt.Errorf("parse envelope json: %w", err)
	}
	kb, err := os.ReadFile(privKeyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	priv, err := nodeenroll.ParseRSAPrivateKeyFromPEM(kb)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	plain, err := nodeenroll.DecryptCredentialEnvelope(priv, &env)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := os.WriteFile(outPath, plain, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}
