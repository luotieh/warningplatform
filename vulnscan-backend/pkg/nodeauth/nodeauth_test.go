package nodeauth_test

import (
	"testing"

	"vulnscan-backend/pkg/nodeauth"
)

func TestHashVerifySecret(t *testing.T) {
	plain := "test-secret-value"
	h, err := nodeauth.HashSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !nodeauth.VerifySecret(plain, h) {
		t.Fatal("expected verify ok")
	}
	if nodeauth.VerifySecret("wrong", h) {
		t.Fatal("expected verify fail")
	}
	if nodeauth.VerifySecret("", h) {
		t.Fatal("empty plain must fail")
	}
	if nodeauth.VerifySecret(plain, "") {
		t.Fatal("empty hash must fail")
	}
}
