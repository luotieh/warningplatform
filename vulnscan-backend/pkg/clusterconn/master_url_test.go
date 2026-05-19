package clusterconn

import "testing"

func TestValidateMasterURL(t *testing.T) {
	if err := ValidateMasterURL("http://127.0.0.1:8090/api"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/api", "127.0.0.1:8090/api", "api"} {
		if err := ValidateMasterURL(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestResolveMasterURLInternalFallback(t *testing.T) {
	opts := Options{
		InternalMasterURL: "http://127.0.0.1:8090/api",
	}
	u, err := ResolveMasterURL(TopologyMasterPublicNodePrivate, "", opts)
	if err != nil || u != "http://127.0.0.1:8090/api" {
		t.Fatalf("got %q err %v", u, err)
	}
}
