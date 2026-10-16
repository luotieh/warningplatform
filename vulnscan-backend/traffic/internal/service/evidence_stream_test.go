package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
)

func TestPhaseOneStreamBudgetsAreIndependent(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 20; i++ {
		m := phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(i+1), nil, false, true)
		m["unused_projection"] = strings.Repeat("x", 900000)
		messages = append(messages, m)
	}
	snap := phaseOneInstallSnapshot(t, s, "large-controlled", 1, messages)
	assets, _ := s.Store.ListAssetsContext(context.Background())
	opts := DefaultSnapshotEvidenceOptions()
	opts.ReportMaterialMode = true
	opts.Facts = evidence.PhaseOneFacts()
	legacy, err := s.SnapshotEvidenceInput(context.Background(), snap, assets, opts)
	if err != nil || legacy.Reason != "snapshot_input_budget_exceeded" {
		t.Fatal("fixture did not exceed legacy budget", legacy.Reason, err)
	}
	opts.StreamFeatures = true
	opts.MaxSnapshotBytes = snapshotTotalBytes
	opts.MaxFeatureBytes = snapshotFeatureBytes
	full, err := s.SnapshotEvidenceInput(context.Background(), snap, assets, opts)
	if err != nil || full.Reason != "" || full.Manifest.LoadedHits != 20 || full.Manifest.Coverage != "complete" {
		t.Fatal("stream failed", full.Reason, full.Manifest.LoadedHits, err)
	}
	if full.Manifest.RetainedFeatureBytes >= 1<<20 || len(full.Manifest.PhaseOne.Contacts) != 20 {
		t.Fatal("retained raw projections or lost contacts")
	}
	opts.MaxSnapshotBytes = 1 << 20
	partial, err := s.SnapshotEvidenceInput(context.Background(), snap, assets, opts)
	if err != nil || partial.Reason != "snapshot_input_budget_exceeded" || partial.Manifest.Coverage == "complete" {
		t.Fatal("total budget became complete", partial.Reason, err)
	}
	opts.MaxSnapshotBytes = snapshotTotalBytes
	opts.MaxFeatureBytes = 100
	partial, err = s.SnapshotEvidenceInput(context.Background(), snap, assets, opts)
	if err != nil || partial.Reason != "snapshot_feature_budget_exceeded" || partial.Manifest.PhaseOne.Complete {
		t.Fatal("feature budget became complete", partial.Reason, err)
	}
}

// Replay the actual K2.7 responses through the final adapter/validation code.
// No model/network call; the saved transcript remains an independently
// inspectable artifact and controlled wire inputs are never called real events.
func TestPhaseOneSavedModelResponseReplay(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", ".local", "round2-model.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("optional saved isolated K2.7 transcript")
	}
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Calls []struct {
			Response string `json:"response"`
		} `json:"calls"`
	}
	if err = json.Unmarshal(raw, &saved); err != nil || len(saved.Calls) != 2 {
		t.Fatal("invalid model transcript", err)
	}
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	for index, protocol := range []string{"http", "dns"} {
		s := phaseOneFixture(t)
		payload := phaseOneHTTP("cmd=636174202f6574632f706173737764")
		if protocol == "dns" {
			name, _ := dnsmessage.NewName("636174202f6574632f706173737764.agent.test.")
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
			payload, _ = m.Pack()
		}
		seq := uint32(100)
		if protocol == "dns" {
			seq = 10
		}
		snap := phaseOneInstallSnapshot(t, s, "model-isolated-"+protocol, 1, []map[string]any{phaseOneWire(t, at, seq, payload, protocol == "dns", false)})
		s.SemanticModel = reportSemanticModelFunc(func(context.Context, evidence.SemanticCall) (string, error) { return saved.Calls[index].Response, nil })
		p := phaseOneRun(t, s, snap, true)
		ids := []string{"C05", "C06"}
		if protocol == "dns" {
			ids = []string{"C07"}
		}
		for _, id := range ids {
			if u := phaseOneUnit(t, p, id); u.Status != "observed" {
				t.Fatal("saved actual model output rejected by final code", id, u)
			}
		}
	}
}

func TestPhaseOneSemanticNegativeMissingAndIncomplete(t *testing.T) {
	for _, protocol := range []string{"http", "dns"} {
		for _, branch := range []string{"contradict", "neutral", "model_error", "incomplete"} {
			t.Run(protocol+"/"+branch, func(t *testing.T) {
				s := phaseOneFixture(t)
				at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
				payload := phaseOneHTTP("cmd=636174202f6574632f706173737764")
				if protocol == "dns" {
					name, _ := dnsmessage.NewName("636174202f6574632f706173737764.agent.test.")
					message := dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
					payload, _ = message.Pack()
				}
				m := phaseOneWire(t, at, 10, payload, protocol == "dns", false)
				if branch == "incomplete" {
					nestedMap(m, "raw_packet")["capture_truncated"] = true
				}
				snap := phaseOneInstallSnapshot(t, s, protocol+branch, 1, []map[string]any{m})
				s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
					if branch == "model_error" {
						return "", fmt.Errorf("controlled offline transport failure")
					}
					raw := acceptedSemanticResponse(t, call)
					if branch == "contradict" {
						raw = strings.ReplaceAll(raw, `"judgement":"support"`, `"judgement":"contradict"`)
					}
					if branch == "neutral" {
						raw = strings.ReplaceAll(raw, `"judgement":"support"`, `"judgement":"neutral"`)
						raw = strings.ReplaceAll(raw, `"strength":"weak"`, `"strength":"none"`)
					}
					return raw, nil
				})
				p := phaseOneRun(t, s, snap, true)
				ids := []string{"C05", "C06"}
				if protocol == "dns" {
					ids = []string{"C07"}
				}
				for _, id := range ids {
					u := phaseOneUnit(t, p, id)
					want := "missing"
					if branch == "contradict" {
						want = "not_observed"
					}
					if u.Status != want || u.Score != 0 {
						t.Fatal(id, branch, u)
					}
				}
			})
		}
	}
}

func TestPhaseOneCompleteTemporalAndHTTPNegatives(t *testing.T) {
	s := phaseOneFixture(t)
	base := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	for day := 0; day < 3; day++ {
		messages := []map[string]any{}
		for i := 0; i < 8; i++ {
			messages = append(messages, phaseOneWire(t, base.Add(time.Duration(day)*24*time.Hour+time.Duration(i*i)*20*time.Minute), uint32(day*100+i), nil, false, true))
		}
		snap := phaseOneInstallSnapshot(t, s, fmt.Sprintf("negative-day-%d", day), int64(day+1), messages)
		if day == 2 {
			p := phaseOneRun(t, s, snap, false)
			for _, id := range []string{"C02", "C03"} {
				u := phaseOneUnit(t, p, id)
				if u.Status != "not_observed" || u.Score != 0 {
					t.Fatal(id, u)
				}
			}
		}
	}
	s = phaseOneFixture(t)
	messages := []map[string]any{}
	for i := 0; i < 8; i++ {
		messages = append(messages, phaseOneWire(t, base.Add(time.Duration(i*i)*time.Minute), uint32(i+1), phaseOneHTTP("cmd=id"), false, false))
	}
	snap := phaseOneInstallSnapshot(t, s, "http-negative-controlled", 1, messages)
	p := phaseOneRun(t, s, snap, false)
	u := phaseOneUnit(t, p, "C04")
	if u.Status != "not_observed" || u.Score != 0 || u.Fact.Measurements.SampleCount != 8 || len(u.Fact.Measurements.HTTPGroups) != 1 {
		t.Fatal(u)
	}
}

func TestPhaseOneUnresolvedFrameExclusionRequiresWireProof(t *testing.T) {
	s := phaseOneFixture(t)
	assets, _ := s.Store.ListAssetsContext(context.Background())
	at := time.Now().UTC()
	m := phaseOneWire(t, at, 1, nil, false, true)
	if phaseOneUnrelatedFrame(m, assets) {
		t.Fatal("eligible frame excluded")
	}
	// Missing/mismatching raw bytes cannot prove an unrelated scope.
	m["src_ip"] = "198.51.100.1"
	m["dst_ip"] = "198.51.100.2"
	if phaseOneUnrelatedFrame(m, assets) {
		t.Fatal("metadata alone excluded unresolved frame")
	}
	raw, _ := hex.DecodeString("a4dcbeef19b08c2a8e81613808004500001c06a64000400186abb4686476903004810800926c65930000")
	icmp := map[string]any{"protocol": "icmp", "src_ip": "180.104.100.118", "dst_ip": "144.48.4.129", "src_port": 0, "dst_port": 0, "raw_packet": map[string]any{"packet_hex": hex.EncodeToString(raw)}}
	if !phaseOneUnrelatedFrame(icmp, assets) {
		t.Fatal("verified ICMP poisoned TCP/UDP coverage")
	}
	icmp["src_ip"] = "198.51.100.1"
	if phaseOneUnrelatedFrame(icmp, assets) {
		t.Fatal("unverified ICMP tuple excluded")
	}
}

func TestPhaseOneSemanticOmissionCannotRefute(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	snap := phaseOneInstallSnapshot(t, s, "semantic-budget", 1, []map[string]any{phaseOneWire(t, at, 1, phaseOneHTTP("cmd=id"), false, false), phaseOneWire(t, at.Add(time.Minute), 2, phaseOneHTTP("cmd=ls"), false, false)})
	opts := DefaultReportSemanticOptions()
	opts.Config.MaxTasks = 1
	s.ReportSemantics = &opts
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		return strings.ReplaceAll(acceptedSemanticResponse(t, c), `"judgement":"support"`, `"judgement":"contradict"`), nil
	})
	p := phaseOneRun(t, s, snap, true)
	if u := phaseOneUnit(t, p, "C05"); u.Status != "missing" || u.Score != 0 {
		t.Fatal("omitted operations became a valid negative", u)
	}
}

func TestPhaseOneHTTPWireClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"ack", nil, "observed"},
		{"response", []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), "observed"},
		{"tls", []byte{23, 3, 3, 0, 2, 0, 1}, "observed"},
		{"unknown", []byte("GET /part"), "missing"},
		{"incomplete-body", []byte("POST /agent HTTP/1.1\r\nHost: agent.test\r\nContent-Length: 50\r\n\r\nx"), "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := phaseOneFixture(t)
			at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
			messages := []map[string]any{}
			for i := 0; i < 8; i++ {
				m := phaseOneWire(t, at.Add(time.Duration(i)*time.Minute), uint32(i+1), phaseOneHTTP("cmd=id"), false, false)
				m["app"] = map[string]any{"http_url": "http://agent.test/agent"}
				messages = append(messages, m)
			}
			m := phaseOneWire(t, at.Add(9*time.Minute), 100, tc.payload, false, false)
			m["app"] = map[string]any{"http_url": "http://agent.test/agent"}
			messages = append(messages, m)
			snap := phaseOneInstallSnapshot(t, s, "http-class-"+tc.name, 1, messages)
			p := phaseOneRun(t, s, snap, false)
			u := phaseOneUnit(t, p, "C04")
			if u.Status != tc.want {
				t.Fatal(u)
			}
			if tc.want == "missing" && u.Score != 0 {
				t.Fatal("incomplete input scored")
			}
		})
	}
}

func TestPhaseOneStructuredRiskOverridesModel(t *testing.T) {
	_, _, b := reportTestBundle(t)
	cfg := evidence.DefaultPhaseOneConfig()
	b.PhaseOne = &PhaseOneEvaluation{Result: evidence.PhaseOneResult{Version: evidence.PhaseOneVersion, Policy: cfg, Score: 15, ScoreMeaning: "policy_evidence_points_not_probability", Units: []evidence.PhaseOneUnit{{ID: "C04", Status: "observed", Score: 15, SourceIDs: []string{"wire"}}}}}
	a := validReportAssessment(b)
	a.EvidenceRisk = &evidence.PhaseOneResult{Score: 999}
	raw, _ := json.Marshal(a)
	got, err := decodeReportAssessment(string(raw), b)
	if err != nil || got.EvidenceRisk == nil || got.EvidenceRisk.Score != 15 || *got.Probability != *a.Probability {
		t.Fatal("backend policy was overridden or changed probability", got, err)
	}
	b.PhaseOne = nil
	got, err = decodeReportAssessment(string(raw), b)
	if err != nil || got.EvidenceRisk != nil {
		t.Fatal("model forged a risk contribution", err)
	}
}

func TestPhaseOneC02SurvivesIncompleteDailyExtension(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 20; i++ {
		messages = append(messages, phaseOneWire(t, at.Add(time.Duration(i*i+1)*time.Second), uint32(i+1), nil, false, true))
	}
	snap := phaseOneInstallSnapshot(t, s, "current-negative", 1, messages)
	assets, _ := s.Store.ListAssetsContext(context.Background())
	opts := DefaultSnapshotEvidenceOptions()
	opts.ReportMaterialMode = true
	opts.Facts = evidence.PhaseOneFacts()
	f, err := s.EvaluateSnapshotFacts(context.Background(), snap, assets, opts, evidence.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ExecutePhaseOne(context.Background(), snap, f, ReportSemanticEvaluation{}, ReportHistory{Status: "unavailable"}, assets, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range p.Result.Units {
		if u.ID == "C02" && u.Status != "not_observed" {
			t.Fatal("C02 inherited history failure", u)
		}
		if u.ID == "C03" && u.Status != "missing" {
			t.Fatal("C03 lost coverage failure", u)
		}
	}
	// Round trip the expanded manifest as formal preparation does before S/C.
	raw, _ := json.Marshal(p.Materials)
	var expanded PhaseOneMaterials
	_ = json.Unmarshal(raw, &expanded)
	f.Manifest.PhaseOne = &expanded
	again, err := s.ExecutePhaseOne(context.Background(), snap, f, ReportSemanticEvaluation{}, ReportHistory{}, assets, false)
	if err != nil {
		t.Fatal(err)
	}
	if digest(p.Facts) != digest(again.Facts) {
		t.Fatal("second formal C join changed deterministic F results")
	}
	expanded.CurrentComplete = false
	partial, err := s.ExecutePhaseOne(context.Background(), snap, f, ReportSemanticEvaluation{}, ReportHistory{}, assets, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range partial.Result.Units {
		if u.ID == "C02" && (u.Status != "missing" || u.Score != 0) {
			t.Fatal("incomplete current timeline became negative", u)
		}
	}
}
