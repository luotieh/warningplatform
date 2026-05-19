package agent

import "testing"

func TestTrimMasterURL(t *testing.T) {
	if got := trimMasterURL("http://127.0.0.1:8090/"); got != "http://127.0.0.1:8090" {
		t.Fatalf("got %q", got)
	}
	if got := trimMasterURL("http://127.0.0.1:8090/api"); got != "http://127.0.0.1:8090/api" {
		t.Fatalf("got %q", got)
	}
}
