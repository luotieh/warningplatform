package nodeenroll_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"vulnscan-backend/pkg/nodeenroll"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	pub, err := nodeenroll.ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"node_uuid":"x","secret":"y"}`)
	env, err := nodeenroll.EncryptCredentialsJSON(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := nodeenroll.DecryptCredentialEnvelope(priv, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("got %q want %q", out, plain)
	}
}
