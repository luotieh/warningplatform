package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCircularClientReceiveIncident(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody TransferIncidentReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"circular_code":"XF-2026-0001"},"msg":""}`))
	}))
	defer srv.Close()

	c := CircularClient{HTTP: srv.Client()}
	// BaseURL 为空 → 用 fallbackBase
	code, err := c.ReceiveIncident(context.Background(), TransferIncidentReq{
		IncidentNo: "evt-1", Name: "测试事件",
	}, "Bearer tok-123", srv.URL)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if code != "XF-2026-0001" {
		t.Fatalf("unexpected code %q", code)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("bearer not forwarded: %q", gotAuth)
	}
	if gotPath != "/api/circular/transfers" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if gotBody.IncidentNo != "evt-1" || gotBody.Name != "测试事件" {
		t.Fatalf("body mismatch: %+v", gotBody)
	}
}

func TestCircularClientMissingBase(t *testing.T) {
	c := CircularClient{HTTP: http.DefaultClient}
	_, err := c.ReceiveIncident(context.Background(), TransferIncidentReq{IncidentNo: "x", Name: "y"}, "", "")
	if err == nil {
		t.Fatal("expected error when base url empty")
	}
}
