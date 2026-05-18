package monitoragent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeHTTPReachableHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !ProbeHTTPReachable(context.Background(), srv.URL) {
		t.Fatal("expected reachable")
	}
}

func TestProbeHTTPReachableOffline(t *testing.T) {
	if ProbeHTTPReachable(context.Background(), "http://127.0.0.1:1") {
		t.Fatal("expected unreachable")
	}
}
