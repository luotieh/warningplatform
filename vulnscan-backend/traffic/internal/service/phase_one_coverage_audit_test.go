package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Candidate screening uses the production F engine. A screen is not report
// acceptance: only the separate frozen-snapshot replay can establish that.
func TestPhaseOneCoverageScreen(t *testing.T) {
	path := os.Getenv("PHASE_ONE_COVERAGE_SCREEN")
	if path == "" {
		t.Skip("optional real coverage inventory")
	}
	var data struct {
		Groups []struct {
			Scope    []string `json:"scope"`
			Contacts []struct {
				ID      string    `json:"id"`
				EventID string    `json:"event_id"`
				Time    time.Time `json:"time"`
				HTTP    *struct {
					Host   string `json:"host"`
					Path   string `json:"path"`
					Method string `json:"method"`
				} `json:"http"`
			} `json:"contacts"`
		} `json:"groups"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	fc := evidence.DefaultConfig()
	fc.Policies = map[evidence.FactID]map[string]float64{"F_BEACON_JITTER": {"ljung_box_lags": 3, "median_relative_tolerance": 0.25}}
	engine, err := evidence.NewEngine(fc)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []any{}
	for _, g := range data.Groups {
		scope := evidence.Scope{AssetID: g.Scope[0], DeviceID: g.Scope[1], EndpointID: g.Scope[2]}
		yes, no := true, false
		req := evidence.Request{EventID: "real-inventory-screen", SnapshotVersion: 1, Facts: []evidence.FactID{"F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_HTTP_ENDPOINT_REPEAT"}, Quality: evidence.Quality{Coverage: evidence.CoverageComplete, SavedTimelineComplete: &yes, CaptureTruncated: &no}}
		http := evidence.HTTPData{Provenance: evidence.Provenance{Verified: true, Complete: true, Version: "screen-only"}}
		for _, c := range g.Contacts {
			req.Hits = append(req.Hits, evidence.Hit{ID: c.ID, OccurredAt: c.Time, Scope: scope})
			if c.HTTP != nil {
				http.Records = append(http.Records, evidence.HTTPRecord{SourceID: c.ID, RequestID: c.ID, Time: c.Time, Method: c.HTTP.Method, URL: "http://" + c.HTTP.Host + c.HTTP.Path})
			}
		}
		if len(http.Records) > 0 {
			for _, r := range http.Records {
				http.SourceIDs = append(http.SourceIDs, r.SourceID)
			}
			http.RequestCandidates = len(http.Records)
			req.Inputs = []evidence.Input{{Scope: scope, HTTP: &http}}
		}
		out, err := engine.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, map[string]any{"scope": g.Scope, "event_id": "cross_event", "count": len(g.Contacts), "findings": out.Findings, "screen_only": true, "coverage_assumed_for_candidate_selection": true})
		events := map[string]bool{}
		for _, c := range g.Contacts {
			events[c.EventID] = true
		}
		for id := range events {
			sub := req
			sub.EventID = id
			sub.Hits = nil
			sub.Inputs = nil
			hh := evidence.HTTPData{Provenance: evidence.Provenance{Verified: true, Complete: true, Version: "screen-only"}}
			for _, c := range g.Contacts {
				if c.EventID != id {
					continue
				}
				sub.Hits = append(sub.Hits, evidence.Hit{ID: c.ID, OccurredAt: c.Time, Scope: scope})
				if c.HTTP != nil {
					hh.SourceIDs = append(hh.SourceIDs, c.ID)
					hh.Records = append(hh.Records, evidence.HTTPRecord{SourceID: c.ID, RequestID: c.ID, Time: c.Time, Method: c.HTTP.Method, URL: "http://" + c.HTTP.Host + c.HTTP.Path})
				}
			}
			if len(hh.Records) > 0 {
				hh.RequestCandidates = len(hh.Records)
				sub.Inputs = []evidence.Input{{Scope: scope, HTTP: &hh}}
			}
			ff, err := engine.Evaluate(context.Background(), sub)
			if err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, map[string]any{"scope": g.Scope, "event_id": id, "count": len(sub.Hits), "findings": ff.Findings, "screen_only": true, "coverage_assumed_for_candidate_selection": true})
		}
	}
	raw, err = json.MarshalIndent(outputs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("PHASE_ONE_COVERAGE_SCREEN_OUTPUT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("screened %d exact asset/device/endpoint/IOC groups", len(outputs))
}

// Frozen effective raw revisions are served only at their archived revision
// watermark. Original database hit IDs, sequences and times remain unchanged.
type coverageArchiveStore struct {
	store.Store
	hits      []store.Hit
	revisions map[string]int64
}

func (s *coverageArchiveStore) HitPage(ctx context.Context, q store.HitQuery) ([]store.Hit, error) {
	allowed := map[string]bool{}
	for _, id := range q.Sources {
		allowed[id] = true
	}
	out := []store.Hit{}
	limit := q.Limit
	if limit < 1 || limit > 500 {
		limit = 200
	}
	for _, h := range s.hits {
		if !allowed[h.EventID] || h.Sequence > q.Watermark || (q.ID != "" && q.ID != h.ID) {
			continue
		}
		if !q.From.IsZero() && h.OccurredAt.Before(q.From) || !q.To.IsZero() && !h.OccurredAt.Before(q.To) {
			continue
		}
		if !q.AfterTime.IsZero() && (h.OccurredAt.Before(q.AfterTime) || h.OccurredAt.Equal(q.AfterTime) && h.ID <= q.AfterID) {
			continue
		}
		out = append(out, h)
		if len(out) == limit {
			break
		}
	}
	return out, ctx.Err()
}
func (s *coverageArchiveStore) HitRevisions(ctx context.Context, ids []string, w int64) (map[string]json.RawMessage, error) {
	for _, id := range ids {
		if expected, ok := s.revisions[id]; !ok || expected != w {
			return nil, fmt.Errorf("unarchived_revision_watermark:%s:%d", id, w)
		}
	}
	return map[string]json.RawMessage{}, ctx.Err()
}
func coverageReadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
func coverageUnpack(t *testing.T, path string) []byte {
	t.Helper()
	var p struct {
		Data string `json:"gzip_base64"`
		SHA  string `json:"sha256"`
	}
	coverageReadJSON(t, path, &p)
	b, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != p.SHA {
		t.Fatal("archive digest mismatch")
	}
	return raw
}

func TestPhaseOneCoverageBindingRows(t *testing.T) {
	dir := os.Getenv("PHASE_ONE_COVERAGE_ARCHIVE")
	if dir == "" {
		t.Skip("optional raw binding rows")
	}
	var inv struct {
		Assets []domain.Asset `json:"assets"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-inventory.json"), &inv)
	var rows struct {
		Samples []store.Hit `json:"samples"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-binding-samples.json"), &rows)
	out := []any{}
	for _, h := range rows.Samples {
		m := map[string]any{}
		d := json.NewDecoder(bytes.NewReader(h.Raw))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		scope, remote, port, ok := snapshotScope(m, inv.Assets)
		if !ok {
			t.Fatal("asset unresolved")
		}
		input := evidence.Input{Scope: scope}
		reportVerifyDatagram(m)
		adaptSnapshotProtocols(&input, h, m, remote, port, true)
		manifest := SnapshotEvidenceManifest{}
		enrichSnapshotProtocols(&input, h, m, &manifest)
		collectPhaseOneMaterials(&manifest, h, m, input, inv.Assets, EvidenceSnapshot{})
		packet := nestedMap(m, "raw_packet")
		checked, problem := snapshotFramePayload(packet, m, &input)
		payload, _, why := snapshotPayload(checked)
		parsedDNS := ""
		var dns dnsmessage.Message
		if dns.Unpack(payload) == nil && len(dns.Questions) == 1 {
			parsedDNS = dns.Questions[0].Name.String()
		}
		out = append(out, map[string]any{"hit_id": h.ID, "origin_event_id": h.EventID, "sequence": h.Sequence, "occurred_at": h.OccurredAt, "not_snapshot_replay": true, "revision_watermark": int64(127451), "ioc_type": m["ioc_type"], "ioc_value": m["ioc_value"], "src_ip": m["src_ip"], "dst_ip": m["dst_ip"], "src_port": m["src_port"], "dst_port": m["dst_port"], "protocol": m["protocol"], "actual_dns_question": parsedDNS, "actual_tls_sni": phaseOneSNI(payload), "frame_problem": problem, "payload_problem": why, "binding": manifest.PhaseOne.Bindings})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "coverage180-binding-row-results.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPhaseOneCoverageFrozenReportReplay(t *testing.T) {
	dir := os.Getenv("PHASE_ONE_COVERAGE_ARCHIVE")
	if dir == "" {
		t.Skip("optional frozen real snapshot archive")
	}
	ctx := context.Background()
	st := &coverageArchiveStore{Store: store.NewMemoryStore(), revisions: map[string]int64{}}
	var inv struct {
		Assets []domain.Asset `json:"assets"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-inventory.json"), &inv)
	for _, a := range inv.Assets {
		if _, err := st.CreateAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	var contexts []struct {
		EventID string          `json:"event_id"`
		Context json.RawMessage `json:"context"`
		Created time.Time       `json:"created_at"`
		Last    *time.Time      `json:"last_seen_at"`
	}
	if err := json.Unmarshal(coverageUnpack(t, filepath.Join(dir, "coverage180-contexts.json")), &contexts); err != nil {
		t.Fatal(err)
	}
	for _, e := range contexts {
		if _, err := st.CreateEvent(domain.Event{EventID: e.EventID, Context: string(e.Context), CreatedAt: e.Created, LastSeenAt: e.Last}); err != nil {
			t.Fatal(err)
		}
	}
	var saved struct {
		Snapshots []struct {
			Key   string           `json:"key"`
			Value EvidenceSnapshot `json:"value"`
		} `json:"snapshots"`
		Segments []struct {
			Key   string       `json:"key"`
			Value EventSegment `json:"value"`
		} `json:"segments"`
	}
	coverageReadJSON(t, filepath.Join(dir, "coverage180-snapshots.json"), &saved)
	for _, r := range saved.Snapshots {
		if err := putRecord(ctx, st, "snapshot", r.Key, r.Value.EventID, r.Value); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range saved.Segments {
		if err := putRecord(ctx, st, "segment", r.Key, r.Key, r.Value); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := filepath.Glob(filepath.Join(dir, "coverage180-raw-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{}
	for _, p := range paths {
		var header struct {
			EventID  string `json:"event_id"`
			Count    int    `json:"count"`
			Revision int64  `json:"revision_watermark"`
		}
		coverageReadJSON(t, p, &header)
		var hits []store.Hit
		if err = json.Unmarshal(coverageUnpack(t, p), &hits); err != nil {
			t.Fatal(err)
		}
		if len(hits) != header.Count {
			t.Fatal("archive count mismatch")
		}
		for _, h := range hits {
			if _, ok := st.revisions[h.ID]; ok {
				t.Fatal("duplicate archived hit")
			}
			st.revisions[h.ID] = header.Revision
		}
		st.hits = append(st.hits, hits...)
		targets = append(targets, header.EventID)
	}
	sort.Slice(st.hits, func(i, j int) bool {
		a, b := st.hits[i], st.hits[j]
		if a.OccurredAt.Equal(b.OccurredAt) {
			return a.ID < b.ID
		}
		return a.OccurredAt.Before(b.OccurredAt)
	})
	outputs := []any{}
	svc := Services{Store: st}
	for _, id := range targets {
		t.Run(id, func(t *testing.T) {
			event, ok := st.GetEvent(id)
			if !ok {
				t.Fatal("event absent")
			}
			p, err := svc.prepareReportInputMode(ctx, event, false)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := svc.EvidenceSnapshot(ctx, id, 0)
			if err != nil {
				t.Fatal(err)
			}
			if p.Evidence.SnapshotVersion != snap.Version || p.Evidence.Watermark != snap.Watermark || p.Evidence.RevisionWatermark != snap.RevisionWatermark {
				t.Fatal("snapshot provenance changed")
			}
			doc := ReportDocument{EventID: id, LayoutVersion: reportFivePartLayout, Evidence: p.Evidence, Assessment: ReportAssessment{Verdict: "insufficient", ProbabilityReason: "本文件验证确定性 F→C→报告渲染链路；未调用模型，未进行事件性质研判。"}}
			doc.Markdown = renderFivePartReport(doc)
			if p.Evidence.PhaseOne != nil && !strings.Contains(doc.Markdown, "C04") {
				t.Fatal("C results absent from formal report renderer")
			}
			out := filepath.Join(dir, "coverage180-report-"+id+".md")
			if err = os.WriteFile(out, []byte(doc.Markdown), 0600); err != nil {
				t.Fatal(err)
			}
			// Exclude packet bodies and semantic payloads from the audit result.
			phase := p.Evidence.PhaseOne
			if phase != nil {
				phase.Materials.Records = nil
			}
			row := map[string]any{"event_id": id, "snapshot_version": snap.Version, "watermark": snap.Watermark, "revision_watermark": snap.RevisionWatermark, "declared_hits": snap.Count, "loaded_hits": p.Evaluation.Manifest.LoadedHits, "raw_bytes": p.Evaluation.Manifest.RawBytes, "coverage": p.Evaluation.Manifest.Coverage, "status": p.Evaluation.Status, "reason": p.Evaluation.Reason, "issues": p.Evaluation.Manifest.Issues, "phase_one": phase, "history": p.Evidence.History, "report_path": out, "report_rendered": true, "model_called": false, "production_writes": 0}
			if os.Getenv("PHASE_ONE_COVERAGE_EXPANDED_DIAGNOSTIC") == "1" {
				opts := DefaultSnapshotEvidenceOptions()
				opts.ReportMaterialMode = true
				opts.Facts = evidence.PhaseOneFacts()
				opts.MaxRawBytes = 512 << 20
				opts.PlatformHistory = p.Evidence.History
				cfg := evidence.DefaultConfig()
				cfg.Policies = map[evidence.FactID]map[string]float64{"F_BEACON_JITTER": {"ljung_box_lags": 3, "median_relative_tolerance": 0.25}}
				eval, err := svc.EvaluateSnapshotFacts(ctx, snap, inv.Assets, opts, cfg)
				if err != nil {
					t.Fatal(err)
				}
				hist := ReportHistory{}
				if p.Evidence.History != nil {
					hist = *p.Evidence.History
				}
				ep, err := svc.ExecutePhaseOne(ctx, snap, eval, ReportSemanticEvaluation{}, hist, inv.Assets, false)
				if err != nil {
					t.Fatal(err)
				}
				protocolCounts := map[string]map[string]int{}
				wireOnly := PhaseOneMaterials{}
				removedFallback := map[string]int{}
				if eval.Manifest.PhaseOne != nil {
					wireOnly = *eval.Manifest.PhaseOne
					wireOnly.Records = append([]PhaseOneRecord(nil), wireOnly.Records...)
					for _, r := range eval.Manifest.PhaseOne.Records {
						key := scopeKey(r.Hit.Scope) + ":" + r.IOCType + ":" + r.IOCValue
						if protocolCounts[key] == nil {
							protocolCounts[key] = map[string]int{}
						}
						c := protocolCounts[key]
						c["records"]++
						if r.HTTPCandidate {
							c["http_candidates"]++
						}
						if r.HTTP != nil {
							if r.RawRequest == "" {
								c["http_record_without_raw_request"]++
							}
							if r.HTTP.Truncated {
								c["http_record_truncated"]++
							}
							if !r.HTTP.Truncated && r.RawRequest != "" {
								c["complete_bound_http_requests_before_dedup"]++
							}
						}
					}
					byID := map[string]store.Hit{}
					for _, h := range st.hits {
						byID[h.ID] = h
					}
					for i := range wireOnly.Records {
						r := &wireOnly.Records[i]
						if !r.HTTPCandidate || r.RawRequest != "" {
							continue
						}
						h := byID[r.Hit.ID]
						m := map[string]any{}
						d := json.NewDecoder(bytes.NewReader(h.Raw))
						d.UseNumber()
						if err := d.Decode(&m); err != nil {
							t.Fatal(err)
						}
						input := evidence.Input{Scope: r.Hit.Scope}
						packet, why := snapshotFramePayload(nestedMap(m, "raw_packet"), m, &input)
						if why != "" {
							continue
						}
						payload, _, why := snapshotPayload(packet)
						if why != "" && why != "payload_bytes_unavailable" {
							continue
						}
						first, _, _ := bytes.Cut(payload, []byte("\r\n"))
						if !bytes.Contains(first, []byte(" HTTP/1.")) {
							r.HTTPCandidate = false
							removedFallback[scopeKey(r.Hit.Scope)+":"+r.IOCType+":"+r.IOCValue]++
						}
					}
				}
				wireFacts, err := phaseOneCurrentFacts(ctx, snap, wireOnly, hist)
				if err != nil {
					t.Fatal(err)
				}
				wireResult, err := evidence.EvaluatePhaseOne(snap.EventID, snap.Version, wireFacts, ReportSemanticEvaluation{}.Result, wireOnly.Bindings, evidence.DefaultPhaseOneConfig())
				if err != nil {
					t.Fatal(err)
				}
				httpTimes := map[string][]time.Time{}
				seenRequests := map[string]bool{}
				for _, r := range wireOnly.Records {
					if !r.HTTPCandidate || r.HTTP == nil || r.HTTP.Truncated || r.RawRequest == "" {
						continue
					}
					scope := scopeKey(r.Hit.Scope) + ":" + r.IOCType + ":" + r.IOCValue
					id := scope + ":" + r.HTTP.RequestID
					if seenRequests[id] {
						continue
					}
					seenRequests[id] = true
					u, err := url.Parse(r.HTTP.URL)
					if err != nil {
						t.Fatal(err)
					}
					path := u.EscapedPath()
					if path == "" {
						path = "/"
					}
					key := scope + ":" + strings.ToLower(u.Host) + path
					httpTimes[key] = append(httpTimes[key], r.HTTP.Time)
				}
				httpStats := map[string]any{}
				for key, ts := range httpTimes {
					sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
					sum, squares := 0.0, 0.0
					for i := 1; i < len(ts); i++ {
						v := ts[i].Sub(ts[i-1]).Seconds()
						sum += v
						squares += v * v
					}
					cv, mean := 0.0, 0.0
					if len(ts) > 1 {
						n := float64(len(ts) - 1)
						mean = sum / n
						if mean > 0 {
							cv = math.Sqrt(math.Max(0, squares/n-mean*mean)) / mean
						}
					}
					httpStats[key] = map[string]any{"unique_complete_requests": len(ts), "first": ts[0], "last": ts[len(ts)-1], "interval_cv": cv, "mean_interval_seconds": mean, "repeat_threshold_pass": len(ts) >= 6 && mean > 0 && cv <= 0.3}
				}
				bundle := buildReportEvidence(event, snap, eval, ReportSemanticEvaluation{}, hist)
				bundle.PhaseOne = &ep
				expandedDoc := doc
				expandedDoc.Evidence = bundle
				expandedDoc.Assessment.ProbabilityReason = "仅本地隔离诊断将原始字节预算提高至512 MiB；未改变生产配置或部署。模型未执行。"
				expandedPath := filepath.Join(dir, "coverage180-expanded-report-"+id+".md")
				if err = os.WriteFile(expandedPath, []byte(renderFivePartReport(expandedDoc)), 0600); err != nil {
					t.Fatal(err)
				}
				ep.Materials.Records = nil
				row["expanded_diagnostic"] = map[string]any{"production_defaults": false, "max_raw_bytes": opts.MaxRawBytes, "loaded_hits": eval.Manifest.LoadedHits, "coverage": eval.Manifest.Coverage, "raw_bytes": eval.Manifest.RawBytes, "status": eval.Status, "reason": eval.Reason, "issues": eval.Manifest.Issues, "phase_one": ep, "report_path": expandedPath, "protocol_record_summary": protocolCounts}
				row["wire_request_denominator_diagnostic"] = map[string]any{"production_implementation": false, "only_app_derived_non_request_records_excluded": true, "removed_non_request_candidates": removedFallback, "result": wireResult, "http_endpoint_statistics": httpStats, "limitations": "This diagnostic tests a supplier correction in isolation; it does not establish acceptance of prepareReportInputMode."}
			}
			outputs = append(outputs, row)
			t.Logf("snapshot=%d loaded=%d/%d status=%s reason=%s phase_one=%t", snap.Version, p.Evaluation.Manifest.LoadedHits, snap.Count, p.Evaluation.Status, p.Evaluation.Reason, phase != nil)
		})
	}
	raw, err := json.MarshalIndent(outputs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "coverage180-report-replay.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
