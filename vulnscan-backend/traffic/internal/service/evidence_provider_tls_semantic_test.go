package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func providerTLSTestHello(name string) []byte {
	vector := func(v []byte) []byte { return append([]byte{byte(len(v) >> 8), byte(len(v))}, v...) }
	sni := append([]byte{0}, vector([]byte(name))...)
	ext := append([]byte{0, 0}, vector(vector(sni))...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = append(body, vector(ext)...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func providerTLSTestPlan(t *testing.T, snap EvidenceSnapshot, input SnapshotEvidenceInput) evidence.SemanticPlan {
	t.Helper()
	r := buildSnapshotSemanticRequest(snap, input, &evidence.Result{}, evidence.SemanticRaw)
	r.Slots = []evidence.SlotKey{{ID: "S12", Target: "c2.domain_lexical", Subtype: "dga_lexical"}}
	engine, err := evidence.NewSemanticEngine(DefaultReportSemanticOptions().Config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestProviderTLSClientHelloLexicalBinding(t *testing.T) {
	at := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		change  func(map[string]any)
		payload []byte
		valid   bool
	}{
		{name: "complete", valid: true},
		{name: "inherited_hint_ack", payload: []byte{}},
		{name: "partial_hello", payload: providerTLSTestHello("agent.test")[:60]},
		{name: "hint_conflict", change: func(m map[string]any) { m["app"] = map[string]any{"tls_sni": "other.test"} }},
		{name: "time_conflict", change: func(m map[string]any) {
			nestedMap(m, "raw_packet")["capture_time"] = at.Add(time.Second).Format(time.RFC3339Nano)
		}},
		{name: "tuple_conflict", change: func(m map[string]any) { m["src_port"] = 1234 }},
		{name: "payload_conflict", change: func(m map[string]any) { nestedMap(m, "raw_packet")["payload_hex"] = "00" }},
		{name: "capture_truncated", change: func(m map[string]any) { nestedMap(m, "raw_packet")["capture_truncated"] = true }},
		{name: "wrong_saved_length", change: func(m map[string]any) { nestedMap(m, "raw_packet")["wire_length"] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload
			if payload == nil {
				payload = providerTLSTestHello("agent.test")
			}
			m := phaseOneWire(t, at, 10, payload, false, false)
			m["app"] = map[string]any{"tls_sni": "agent.test"}
			if tc.change != nil {
				tc.change(m)
			}
			raw, _ := json.Marshal(m)
			snap := EvidenceSnapshot{EventID: "tls-event", Version: 1, Count: 1}
			out, _, _, err := assembleProviderTraffic(snap, []domain.Asset{{ID: "asset-a", Address: "192.0.2.1", Status: 1}}, []store.Hit{{ID: "tls-hit", EventID: snap.EventID, OccurredAt: at, Raw: raw}}, evidence.AnalysisWindow{Start: at, End: at.Add(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			plan := providerTLSTestPlan(t, snap, out)
			if len(plan.Tasks) != 0 && !tc.valid || tc.valid && len(plan.Tasks) != 1 {
				t.Fatalf("unexpected S12 tasks=%d valid=%v", len(plan.Tasks), tc.valid)
			}
			if tc.valid {
				task := plan.Tasks[0]
				if task.SubjectID != "operation:tls-hit" || task.MaxStrength != "weak" || len(task.Facts) != 0 {
					t.Fatal("TLS lexical escaped its contract", task)
				}
				if out.Request.Inputs[0].TLS.Complete || len(out.Manifest.PhaseOne.Contacts) != 0 {
					t.Fatal("SNI promoted full TLS or contact")
				}
			}
		})
	}
	// A valid early SNI must not hide a malformed later extension.
	hello := providerTLSTestHello("agent.test")
	hello = append(hello, 0)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	n := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(n>>16), byte(n>>8), byte(n)
	extOffset := 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1
	binary.BigEndian.PutUint16(hello[extOffset:extOffset+2], uint16(len(hello)-extOffset-2))
	if providerCompleteClientHelloSNI(hello) != "" {
		t.Fatal("accepted malformed extension after SNI")
	}
}

func TestProviderTLSClientHelloRealArchive(t *testing.T) {
	dir := os.Getenv("REAL_CHAIN_PARITY_ARCHIVE")
	if dir == "" {
		t.Skip("requires immutable real archive")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "coverage180-raw-ly-75e2c9ed-4a1b-4d20-b676-5c81c9725aa8.json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Data      string `json:"gzip_base64"`
		SHA       string `json:"sha256"`
		Version   int64  `json:"snapshot_version"`
		Watermark int64  `json:"watermark"`
		Revision  int64  `json:"revision_watermark"`
	}
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	compressed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(io.LimitReader(z, 128<<20))
	if err != nil {
		t.Fatal(err)
	}
	z.Close()
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != env.SHA || env.SHA != "cb2af4c8d61555bd83ee33f146ef79184340c3056b53d1545811179b10d591cc" {
		t.Fatal("real archive changed")
	}
	var hits []store.Hit
	if err = json.Unmarshal(payload, &hits); err != nil {
		t.Fatal(err)
	}
	inv, err := os.ReadFile(filepath.Join(dir, "coverage180-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Assets []domain.Asset `json:"assets"`
	}
	if err = json.Unmarshal(inv, &inventory); err != nil {
		t.Fatal(err)
	}
	start, end := hits[0].OccurredAt, hits[0].OccurredAt
	for _, h := range hits {
		if h.OccurredAt.Before(start) {
			start = h.OccurredAt
		}
		if h.OccurredAt.After(end) {
			end = h.OccurredAt
		}
	}
	snap := EvidenceSnapshot{EventID: "ly-75e2c9ed-4a1b-4d20-b676-5c81c9725aa8", Version: env.Version, Watermark: env.Watermark, RevisionWatermark: env.Revision, Count: int64(len(hits))}
	out, _, _, err := assembleProviderTraffic(snap, inventory.Assets, hits, evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
	if err != nil {
		t.Fatal(err)
	}
	// Local material-only subset preserves the original 34 rows/bytes. It is
	// deliberately not presented as a full published-snapshot replay.
	var sniRows []store.Hit
	for _, h := range hits {
		var m map[string]any
		if json.Unmarshal(h.Raw, &m) == nil && asString(nestedMap(m, "app")["tls_sni"]) != "" {
			sniRows = append(sniRows, h)
		}
	}
	subset, _, _, err := assembleProviderTraffic(snap, inventory.Assets, sniRows, evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
	if err != nil {
		t.Fatal(err)
	}
	plan := providerTLSTestPlan(t, snap, subset)
	var tlsSubjects []string
	for _, o := range subset.SemanticObservations {
		if o.TLSSNI != "" {
			tlsSubjects = append(tlsSubjects, "operation:"+o.HitID)
		}
	}
	tasks := map[string]bool{}
	for _, task := range plan.Tasks {
		tasks[task.SubjectID] = true
	}
	for _, subject := range tlsSubjects {
		if !tasks[subject] {
			for _, x := range plan.Executions {
				if x.SubjectID == subject {
					t.Fatalf("real SNI not planned: subject=%s reason=%s", subject, x.Reason)
				}
			}
			t.Fatal("real complete SNI did not reach S12", subject)
		}
	}
	t.Logf("archive_hits=%d default_observations=%d material_only_subset_rows=%d subset_tls_subjects=%d subset_S12_tasks=%d snapshot=%d watermark=%d revision=%d model_calls=0", len(hits), len(out.SemanticObservations), len(sniRows), len(tlsSubjects), len(plan.Tasks), snap.Version, snap.Watermark, snap.RevisionWatermark)
	if len(tlsSubjects) != 6 {
		t.Fatal("expected 6 hit-bound SNI subjects from 3 complete original frames", tlsSubjects)
	}
	// Local old-collector behavior control only: these six TLS frames could
	// not create observations before the SNI branch existed. Omitting them
	// solely for material selection reveals the legacy queue they displaced.
	// Original archive/snapshot files remain untouched; this is not a frozen
	// published before run or a claim about query membership.
	tlsIDs := map[string]bool{}
	for _, o := range subset.SemanticObservations {
		if o.TLSSNI != "" {
			tlsIDs[o.HitID] = true
		}
	}
	var legacyCandidates []store.Hit
	for _, h := range hits {
		if !tlsIDs[h.ID] {
			legacyCandidates = append(legacyCandidates, h)
		}
	}
	legacy, _, _, err := assembleProviderTraffic(snap, inventory.Assets, legacyCandidates, evidence.AnalysisWindow{Start: start, End: end.Add(time.Nanosecond)})
	if err != nil {
		t.Fatal(err)
	}
	newIDs := map[string]bool{}
	for _, o := range out.SemanticObservations {
		newIDs[o.HitID] = true
	}
	var displaced []string
	for _, o := range legacy.SemanticObservations {
		if !newIDs[o.HitID] {
			displaced = append(displaced, o.HitID)
		}
	}
	sort.Strings(displaced)
	defaultPlan := func(input SnapshotEvidenceInput) evidence.SemanticPlan {
		r := buildSnapshotSemanticRequest(snap, input, &evidence.Result{}, evidence.SemanticRaw)
		e, _ := evidence.NewSemanticEngine(DefaultReportSemanticOptions().Config)
		p, err := e.Plan(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	beforeDefault, afterDefault := defaultPlan(legacy), defaultPlan(out)
	readyBefore := map[string]bool{}
	for _, task := range beforeDefault.Tasks {
		readyBefore[task.Slot.Key.String()+"@"+task.SubjectID] = true
	}
	for _, task := range afterDefault.Tasks {
		delete(readyBefore, task.Slot.Key.String()+"@"+task.SubjectID)
	}
	var lostReady []string
	for k := range readyBefore {
		lostReady = append(lostReady, k)
	}
	sort.Strings(lostReady)
	defaultTLSReady, defaultTLSSkipped := 0, 0
	for _, x := range afterDefault.Executions {
		if x.Slot.ID == "S12" && x.Slot.Subtype == "dga_lexical" && tlsIDs[x.SubjectID[len("operation:"):]] {
			if x.Status == "planned" {
				defaultTLSReady++
			} else {
				defaultTLSSkipped++
			}
		}
	}
	t.Logf("local_old_collector_control observations=%d displaced_existing=%d ids=%v default_tasks=%d->%d default_tls_ready=%d default_tls_skipped=%d lost_ready=%v", len(legacy.SemanticObservations), len(displaced), displaced, len(beforeDefault.Tasks), len(afterDefault.Tasks), defaultTLSReady, defaultTLSSkipped, lostReady)
	if len(displaced) != 0 || len(lostReady) != 0 || digest(legacy.SemanticObservations) != digest(out.SemanticObservations) {
		t.Fatal("TLS selection displaced existing HTTP/DNS material")
	}
	if defaultTLSReady != 0 {
		t.Fatal("saturated default archive unexpectedly gained TLS tasks")
	}
}
