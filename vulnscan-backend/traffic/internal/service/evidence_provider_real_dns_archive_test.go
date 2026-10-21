package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// This opt-in test consumes archived packets, not a published collection. No
// snapshot Sources/Count, segment membership or missing ingestion IDs are made up.
func realDNSArchiveSubset(t *testing.T) ([]store.Hit, []domain.Asset) {
	t.Helper()
	dir := os.Getenv("REAL_DNS_ARCHIVE_SUBSET")
	if dir == "" {
		t.Skip("requires original REAL_DNS_ARCHIVE_SUBSET; never substitute synthetic DNS")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw := read("source-hits.json")
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "2376c882dcc5a077c1b8d0c6797d119724914cdad67148c9cf37fe86d1b8ef31" {
		t.Fatal("original DNS archive payload changed")
	}
	var hits []store.Hit
	if err := json.Unmarshal(raw, &hits); err != nil {
		t.Fatal(err)
	}
	var assets []domain.Asset
	if err := json.Unmarshal(read("matched-assets.json"), &assets); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 4 || len(assets) != 1 || assets[0].ID != "asset-0f4ef4d8ee0aa302" || assets[0].Address != "180.104.100.118" || assets[0].Status != 1 {
		t.Fatal("real original rows or registered asset changed")
	}
	for i, h := range hits {
		if h.EventID != "ly-1ffb21c0-18cc-44d5-81f7-f5e4bda651f4" || h.Sequence != int64(48558+i) || h.DedupKey != "" || !h.ReceivedAt.IsZero() {
			t.Fatal("original hit identity rewritten", h.ID)
		}
	}
	return hits, assets
}

func TestProviderRealDNSArchiveSubsetConsumers(t *testing.T) {
	hits, assets := realDNSArchiveSubset(t)
	before := digest(hits)
	// These four metadata values are in the original envelope. The window is
	// merely the observed packet bounds, never a published/complete window.
	snap := EvidenceSnapshot{EventID: hits[0].EventID, Version: 4, Watermark: 48561, RevisionWatermark: 0}
	w := evidence.AnalysisWindow{Start: hits[0].OccurredAt, End: hits[3].OccurredAt.Add(time.Nanosecond)}
	input, _, _, err := assembleProviderTraffic(snap, assets, hits, w)
	if err != nil {
		t.Fatal(err)
	}
	if digest(hits) != before || input.Request.Quality.Coverage != evidence.CoveragePartial || input.Manifest.PhaseOne.Complete || input.Manifest.PhaseOne.CurrentComplete {
		t.Fatal("packet consumer mutated archive or invented full window")
	}
	for _, in := range input.Request.Inputs {
		if in.DNS == nil || in.DNS.Complete || in.Network == nil || in.Network.Complete {
			t.Fatal("per-question evidence invented a complete DNS/network window")
		}
	}
	verified, rejected, contacts := map[string]int{}, map[string]int{}, map[string]int{}
	for _, b := range input.Manifest.PhaseOne.Bindings {
		if b.Verified {
			verified[b.IOCType]++
		} else {
			rejected[b.IOCType]++
			if b.Reason != "ioc_type_value_not_at_wire_field" {
				t.Fatal("unexpected wire rejection", b)
			}
		}
		if b.IOCType == "domain" && b.IOCValue != "lsax.org" {
			t.Fatal("IOC replaced by question name", b)
		}
	}
	physicalContacts := map[string]bool{}
	for _, c := range input.Manifest.PhaseOne.Contacts {
		contacts[c.IOCType]++
		physicalContacts[c.ID] = true
		if c.Kind != "dns_question" || !c.Time.Equal(hits[0].OccurredAt) {
			t.Fatal("response counted as an active DNS contact", c)
		}
	}
	if verified["ip"] != 2 || rejected["ip"] != 0 || contacts["ip"] != 1 || len(physicalContacts) != 1 {
		t.Fatal("IP bindings or physical request population changed", verified, rejected, contacts)
	}
	stage := os.Getenv("REAL_DNS_ARCHIVE_EXPECT_STAGE")
	if stage == "before" {
		if verified["domain"] != 0 || rejected["domain"] != 2 || contacts["domain"] != 0 {
			t.Fatal("original whole-domain exact-match baseline was not reproduced", verified, rejected, contacts)
		}
	} else {
		if stage != "" && stage != "after" {
			t.Fatal("unknown explicit replay stage", stage)
		}
		stage = "after"
		if verified["domain"] != 2 || rejected["domain"] != 0 || contacts["domain"] != 1 {
			t.Fatal("real subdomain IOC binding not restored", verified, rejected, contacts)
		}
	}
	frames, queries, responses := map[string]bool{}, 0, 0
	for _, h := range hits {
		var raw map[string]any
		if err := json.Unmarshal(h.Raw, &raw); err != nil {
			t.Fatal(err)
		}
		packet := nestedMap(raw, "raw_packet")
		frame := asString(packet["packet_hex"])
		if frames[frame] {
			continue
		}
		frames[frame] = true
		data, err := hex.DecodeString(asString(packet["payload_hex"]))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := snapshotDecodeDNS(raw, data)
		if err != nil || len(msg.Questions) != 1 || msg.Questions[0].Name.String() != "zz-direct-test.oob.lsax.org." {
			t.Fatal("original DNS question did not decode", err)
		}
		if msg.Response {
			responses++
			if int(msg.RCode) != 3 {
				t.Fatal("original NXDOMAIN response changed")
			}
		} else {
			queries++
		}
	}
	if len(frames) != 2 || queries != 1 || responses != 1 {
		t.Fatal("IOC duplicates inflated actual DNS operation count", len(frames), queries, responses)
	}
	result := &evidence.Result{}
	for _, r := range input.Manifest.PhaseOne.Records {
		if r.DNS == nil {
			continue
		}
		facts, err := phaseOneDNSFact(context.Background(), snap, r)
		if err != nil || len(facts) != 1 || facts[0].FactID != "F_DNS_ENCODED_LABEL" || facts[0].Status != evidence.NotObserved || len(facts[0].SourceIDs) != 1 || facts[0].SourceIDs[0] != r.Hit.ID {
			t.Fatal("real non-encoded question must be an exact-source effective negative", facts, err)
		}
		result.Findings = append(result.Findings, facts...)
	}
	if len(result.Findings) != 4 {
		t.Fatal("per-hit source references lost; four references are not four questions", result.Findings)
	}
	req := buildSnapshotSemanticRequest(snap, input, result, evidence.SemanticRaw)
	req.Slots = []evidence.SlotKey{{ID: "S04", Target: "c2.dns_encoded_intent"}, {ID: "S12", Target: "c2.domain_lexical", Subtype: "dga_lexical"}}
	engine, err := evidence.NewSemanticEngine(evidence.DefaultSemanticConfig())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(context.Background(), req)
	if err != nil || len(plan.Tasks) != 4 {
		t.Fatal("expected original four independently cited lexical material subjects", len(plan.Tasks), plan.Executions, err)
	}
	for _, task := range plan.Tasks {
		if task.Slot.Key.String() != "S12/c2.domain_lexical/dga_lexical" || task.MaxStrength != "weak" {
			t.Fatal("nonencoded question incorrectly enabled encoded intent", task.Slot.Key)
		}
		for _, m := range task.Materials {
			if m.Kind == "domain" && m.Text != "zz-direct-test.oob.lsax.org" {
				t.Fatal("lexical subject used IOC instead of original question", m)
			}
			if len(m.SourceIDs) != 1 || task.SubjectID != "operation:"+m.SourceIDs[0] || !strings.HasPrefix(m.ID, task.SubjectID+":") {
				t.Fatal("cross-question material source borrowing", m)
			}
		}
	}
	calls := 0
	semantic, err := engine.Evaluate(context.Background(), req, reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, call), nil
	}))
	if err != nil || calls == 0 || len(semantic.Findings) != 4 {
		t.Fatal("controlled Stub structural validation failed", semantic, err)
	}
	for _, f := range semantic.Findings {
		if f.Slot.String() != "S12/c2.domain_lexical/dga_lexical" || f.Strength != "weak" || f.StructureValidation != "passed" || f.BehaviorOutcome != "not_established" {
			t.Fatal("lexical structure escalated beyond its contract", f)
		}
	}
	t.Logf("real_archived_packet_subset stage=%s hits=4 physical_requests=%d responses=%d verified=%v rejected=%v contacts_by_ioc=%v unique_physical_contacts=%d encoded_negative_source_refs=%d lexical_stub_findings=%d collection_end_to_end=not_run", stage, queries, responses, verified, rejected, contacts, len(physicalContacts), len(result.Findings), len(semantic.Findings))
}
