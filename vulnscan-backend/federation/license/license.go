package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// LicensePayload is the data that gets signed.
type LicensePayload struct {
	LicenseID   string    `json:"license_id"`
	TenantID    string    `json:"tenant_id"`
	SubMasterID string    `json:"sub_master_id,omitempty"`
	MaxWorkers  int       `json:"max_workers"`
	MaxTargets  int       `json:"max_targets"`
	MaxScansDay int       `json:"max_scans_day"`
	Modules     []string  `json:"modules"`
	Features    []string  `json:"features"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	GracePeriod int       `json:"grace_period"`
}

// SignedLicense is the full license file with payload and signature.
type SignedLicense struct {
	Payload   LicensePayload `json:"payload"`
	Signature string         `json:"signature"`
}

// Issuer creates and signs licenses (runs on Central Master).
type Issuer struct {
	privateKey *rsa.PrivateKey
}

func NewIssuer(privateKeyPath string) (*Issuer, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key file")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key: %w (also tried PKCS8: %w)", err, err2)
		}
		rsaKey, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		key = rsaKey
	}

	return &Issuer{privateKey: key}, nil
}

// NewIssuerFromKey creates an issuer directly from a private key (for testing).
func NewIssuerFromKey(key *rsa.PrivateKey) *Issuer {
	return &Issuer{privateKey: key}
}

// Issue signs a license payload and returns the signed license.
func (iss *Issuer) Issue(payload LicensePayload) (*SignedLicense, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, iss.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign license: %w", err)
	}

	return &SignedLicense{
		Payload:   payload,
		Signature: hex.EncodeToString(sig),
	}, nil
}

// --- Validator (runs on Sub-Master) ---

type Validator struct {
	publicKey *rsa.PublicKey

	mu            sync.RWMutex
	cachedLicense *SignedLicense
	offlineSince  *time.Time
}

func NewValidator(publicKeyPath string) (*Validator, error) {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in public key file")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}

	return &Validator{publicKey: rsaPub}, nil
}

// NewValidatorFromKey creates a validator from a public key (for testing).
func NewValidatorFromKey(key *rsa.PublicKey) *Validator {
	return &Validator{publicKey: key}
}

// Validate checks the license signature and expiration.
func (v *Validator) Validate(lic *SignedLicense) error {
	data, err := json.Marshal(lic.Payload)
	if err != nil {
		return err
	}

	sigBytes, err := hex.DecodeString(lic.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// LoadAndValidate loads a license file and validates it.
func (v *Validator) LoadAndValidate(path string) (*SignedLicense, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read license file: %w", err)
	}

	var lic SignedLicense
	if err := json.Unmarshal(data, &lic); err != nil {
		return nil, fmt.Errorf("parse license: %w", err)
	}

	if err := v.Validate(&lic); err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.cachedLicense = &lic
	v.mu.Unlock()

	return &lic, nil
}

// Status returns the current license status.
func (v *Validator) Status() string {
	v.mu.RLock()
	lic := v.cachedLicense
	offline := v.offlineSince
	v.mu.RUnlock()

	if lic == nil {
		return "no_license"
	}

	now := time.Now()

	if now.Before(lic.Payload.ExpiresAt) {
		return "active"
	}

	graceEnd := lic.Payload.ExpiresAt.AddDate(0, 0, lic.Payload.GracePeriod)
	if now.Before(graceEnd) {
		return "grace_period"
	}

	if offline != nil {
		offlineGrace := offline.AddDate(0, 0, lic.Payload.GracePeriod)
		if now.Before(offlineGrace) {
			return "offline_grace"
		}
	}

	return "expired"
}

// CheckQuota validates whether a specific quota is within limits.
func (v *Validator) CheckQuota(quotaType string, current int) bool {
	v.mu.RLock()
	lic := v.cachedLicense
	v.mu.RUnlock()

	if lic == nil {
		return false
	}

	status := v.Status()
	if status == "expired" || status == "no_license" {
		return false
	}

	switch quotaType {
	case "workers":
		return current < lic.Payload.MaxWorkers
	case "targets":
		return current < lic.Payload.MaxTargets
	case "scans_day":
		return current < lic.Payload.MaxScansDay
	default:
		return true
	}
}

// HasModule checks if a module is allowed by the license.
func (v *Validator) HasModule(module string) bool {
	v.mu.RLock()
	lic := v.cachedLicense
	v.mu.RUnlock()

	if lic == nil || len(lic.Payload.Modules) == 0 {
		return true
	}

	for _, m := range lic.Payload.Modules {
		if m == module || m == "*" {
			return true
		}
	}
	return false
}

// SetOffline marks the beginning of an offline period.
func (v *Validator) SetOffline() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.offlineSince == nil {
		now := time.Now()
		v.offlineSince = &now
		slog.Warn("[License] 进入离线模式")
	}
}

// ClearOffline clears the offline state (connection restored).
func (v *Validator) ClearOffline() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.offlineSince = nil
}
