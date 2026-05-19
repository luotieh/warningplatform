package clusterconn

import "testing"

func TestResolveMasterURL(t *testing.T) {
	opts := Options{PublicMasterURL: "https://scan.example.com/api"}

	u, err := ResolveMasterURL(TopologyMasterPublicNodePrivate, "", opts)
	if err != nil || u != "https://scan.example.com/api" {
		t.Fatalf("got %q err %v", u, err)
	}

	u, err = ResolveMasterURL("", "https://custom/api", opts)
	if err != nil || u != "https://custom/api" {
		t.Fatalf("request override: %q %v", u, err)
	}

	_, err = ResolveMasterURL(TopologyMasterPrivateNodePublic, "", Options{})
	if err == nil {
		t.Fatal("expected error when public and internal url missing")
	}

	_, err = ResolveMasterURL("", "/api", opts)
	if err == nil {
		t.Fatal("expected error for path-only master_url")
	}
}
