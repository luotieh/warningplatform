// Package nodeenroll builds machine-bound enrollment payloads for scan node onboarding.
package nodeenroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const enrollmentVersion = 1

// EnrollmentFile is written on the node and uploaded to the master to issue credentials.
type EnrollmentFile struct {
	Version            int      `json:"version"`
	MachineFingerprint string   `json:"machine_fingerprint"`
	Hostname           string   `json:"hostname"`
	PrimaryMAC         string   `json:"primary_mac"`
	MACAddresses       []string `json:"mac_addresses"`
	OSArch             string   `json:"os_arch"`
	RequestedAt        string   `json:"requested_at"`
	Nonce              string   `json:"nonce"`
	// PublicKeyPEM is PKIX PEM (RSA). When set, the master returns an encrypted credential envelope only.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// MachineFingerprint is a stable identifier from hostname + hardware MACs (sorted).
func MachineFingerprint(hostname string, macs []string) string {
	hn := strings.TrimSpace(strings.ToLower(hostname))
	cp := append([]string(nil), macs...)
	for i := range cp {
		cp[i] = strings.TrimSpace(strings.ToLower(cp[i]))
	}
	sort.Strings(cp)
	sum := sha256.Sum256([]byte(hn + "\n" + strings.Join(cp, "|")))
	return hex.EncodeToString(sum[:])
}

// ListMACAddresses returns non-loopback hardware MACs (best effort).
func ListMACAddresses() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var macs []string
	for _, iface := range ifs {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		m := iface.HardwareAddr.String()
		if m == "" || m == "00:00:00:00:00:00" {
			continue
		}
		macs = append(macs, m)
	}
	sort.Strings(macs)
	return macs, nil
}

// BuildEnrollmentFile collects local facts and returns JSON-serializable enrollment data.
func BuildEnrollmentFile() (*EnrollmentFile, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	macs, err := ListMACAddresses()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	if len(macs) == 0 {
		return nil, fmt.Errorf("no non-loopback MAC found; set a stable network adapter before enrolling")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	primary := macs[0]
	fp := MachineFingerprint(hostname, macs)
	return &EnrollmentFile{
		Version:            enrollmentVersion,
		MachineFingerprint: fp,
		Hostname:           hostname,
		PrimaryMAC:         primary,
		MACAddresses:       macs,
		OSArch:             runtime.GOOS + "/" + runtime.GOARCH,
		RequestedAt:        time.Now().UTC().Format(time.RFC3339),
		Nonce:              hex.EncodeToString(nonce),
	}, nil
}

// Validate checks that the fingerprint matches embedded fields and required fields exist.
func Validate(f *EnrollmentFile) error {
	if f == nil {
		return fmt.Errorf("enrollment payload is nil")
	}
	if strings.TrimSpace(f.Nonce) == "" {
		return fmt.Errorf("nonce is required")
	}
	if len(f.MACAddresses) == 0 {
		return fmt.Errorf("mac_addresses is required")
	}
	want := MachineFingerprint(f.Hostname, f.MACAddresses)
	if strings.TrimSpace(f.MachineFingerprint) != want {
		return fmt.Errorf("machine_fingerprint mismatch (possible tampering)")
	}
	if strings.TrimSpace(f.PublicKeyPEM) != "" {
		if _, err := ParseRSAPublicKeyFromPEM(f.PublicKeyPEM); err != nil {
			return fmt.Errorf("public_key_pem: %w", err)
		}
	}
	return nil
}

// MarshalIndentPretty returns indented JSON for writing to disk.
func MarshalIndentPretty(f *EnrollmentFile) ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}
