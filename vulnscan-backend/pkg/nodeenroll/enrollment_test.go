package nodeenroll_test

import (
	"testing"

	"vulnscan-backend/pkg/nodeenroll"
)

func TestMachineFingerprintStable(t *testing.T) {
	fp := nodeenroll.MachineFingerprint("Host-A", []string{"bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa"})
	fp2 := nodeenroll.MachineFingerprint("host-a", []string{"AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"})
	if fp != fp2 {
		t.Fatalf("expected stable fingerprint, got %q vs %q", fp, fp2)
	}
}

func TestValidateEnrollment(t *testing.T) {
	f, err := nodeenroll.BuildEnrollmentFile()
	if err != nil {
		t.Skip(err)
	}
	if err := nodeenroll.Validate(f); err != nil {
		t.Fatal(err)
	}
	f.MachineFingerprint = "deadbeef"
	if err := nodeenroll.Validate(f); err == nil {
		t.Fatal("expected tamper error")
	}
}
