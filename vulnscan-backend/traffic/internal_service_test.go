package traffic

import (
	"archive/zip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	trafficconfig "vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestValidEvidencePath(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/api/v1/evidence/node-001/2026-08-06/evt-xxx.pcap", true},
		{"/api/v1/evidence/a/b/c.pcap", true},
		{"/api/v1/evidence/../etc/passwd", false},
		{"/other/path.pcap", false},
		{"http://evil/api/v1/evidence/x", false},
		{"/api/v1/evidence/a\\b.pcap", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validEvidencePath(c.path); got != c.ok {
			t.Errorf("validEvidencePath(%q)=%v, want %v", c.path, got, c.ok)
		}
	}
}

func TestEvidenceFileRequiresNodeMapping(t *testing.T) {
	st := store.NewMemoryStore()
	_, err := st.CreateEvent(domain.Event{
		EventID: "evt-evidence-1",
		Context: `{"device_id":"node-x","evidence_files":[{"name":"a.pcap","type":"pcap","path_ref":"/api/v1/evidence/node-x/2026-08-06/a.pcap"}]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewInternalService(trafficconfigForTest(), trafficserviceForTest(st))
	_, _, _, err = svc.EvidenceFile(context.Background(), "evt-evidence-1", 0)
	if err == nil || !strings.Contains(err.Error(), "未配置节点") {
		t.Fatalf("expected node mapping error, got %v", err)
	}
}

func TestEvidenceArchiveZip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/evidence/node-x/2026-08-06/a.pcap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		_, _ = w.Write([]byte("PCAP-A"))
	})
	mux.HandleFunc("/api/v1/evidence/node-x/2026-08-06/b.pcap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		_, _ = w.Write([]byte("PCAP-B"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{
		EventID: "evt-archive-1",
		Context: `{"device_id":"node-x","evidence_files":[
			{"name":"a.pcap","path_ref":"/api/v1/evidence/node-x/2026-08-06/a.pcap","device_id":"node-x","occ_idx":0,"occ_time":"2026-08-06T10:00:00Z"},
			{"name":"b.pcap","path_ref":"/api/v1/evidence/node-x/2026-08-06/b.pcap","device_id":"node-x","occ_idx":1,"occ_time":"2026-08-06T10:01:00Z"},
			{"name":"missing.pcap","path_ref":"/api/v1/evidence/node-x/2026-08-06/missing.pcap","device_id":"node-x","occ_idx":2,"occ_time":"2026-08-06T10:02:00Z"}
		]}`,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := trafficconfig.Config{EvidenceNodes: map[string]string{"node-x": srv.URL}}
	svc := NewInternalService(cfg, trafficserviceForTest(st))
	dir, res, err := svc.EvidenceArchive(context.Background(), "evt-archive-1")
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		t.Fatal("expected temp dir")
	}
	defer os.RemoveAll(dir)
	if res.Total != 3 || res.Succeeded != 2 || res.Failed != 1 {
		t.Fatalf("result=%+v", res)
	}
	if res.Truncated {
		t.Fatal("unexpected truncated")
	}
	entries := readZipEntries(t, dir)
	if string(entries["000_20260806T100000Z_a.pcap"]) != "PCAP-A" {
		t.Fatalf("entry a missing/wrong: %v", len(entries["000_20260806T100000Z_a.pcap"]))
	}
	if string(entries["001_20260806T100100Z_b.pcap"]) != "PCAP-B" {
		t.Fatalf("entry b missing/wrong: %v", len(entries["001_20260806T100100Z_b.pcap"]))
	}
	manifest, ok := entries["_下载失败清单.txt"]
	if !ok || !strings.Contains(string(manifest), "missing.pcap") {
		t.Fatalf("failure manifest missing: %s", manifest)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temp dir should be removed, stat err=%v", err)
	}
}

func TestEvidenceArchiveAllFailed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{
		EventID: "evt-archive-allfail",
		Context: `{"device_id":"node-x","evidence_files":[
			{"name":"a.pcap","path_ref":"/api/v1/evidence/node-x/a.pcap","device_id":"node-x","occ_idx":0},
			{"name":"b.pcap","path_ref":"/api/v1/evidence/node-x/b.pcap","device_id":"node-x","occ_idx":1}
		]}`,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := trafficconfig.Config{EvidenceNodes: map[string]string{"node-x": srv.URL}}
	svc := NewInternalService(cfg, trafficserviceForTest(st))
	dir, _, err := svc.EvidenceArchive(context.Background(), "evt-archive-allfail")
	if dir != "" {
		os.RemoveAll(dir)
	}
	if err == nil || !strings.Contains(err.Error(), "全部") {
		t.Fatalf("expected all-failed error, got %v", err)
	}
}

func TestEvidenceArchiveNoEvidence(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{EventID: "evt-archive-empty", Context: `{"device_id":"node-x"}`}); err != nil {
		t.Fatal(err)
	}
	svc := NewInternalService(trafficconfigForTest(), trafficserviceForTest(st))
	if _, _, err := svc.EvidenceArchive(context.Background(), "evt-archive-empty"); err != errEvidenceNotFound {
		t.Fatalf("want errEvidenceNotFound, got %v", err)
	}
	if _, _, err := svc.EvidenceArchive(context.Background(), "evt-missing"); err != errEventNotFound {
		t.Fatalf("want errEventNotFound, got %v", err)
	}
}

func readZipEntries(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "archive.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(f, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(zr.File))
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[zf.Name] = b
	}
	return out
}

func trafficconfigForTest() trafficconfig.Config {
	return trafficconfig.Config{EvidenceNodes: map[string]string{}}
}

func trafficserviceForTest(st store.Store) trafficservice.Services {
	return trafficservice.Services{Store: st}
}
