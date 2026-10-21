package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type remainingIndependentHistoryReader struct {
	store.EvidenceReader
	calls int
	query store.HistoryQuery
	rows  []domain.Event
}

func (r *remainingIndependentHistoryReader) HistoryCandidates(_ context.Context, q store.HistoryQuery) ([]domain.Event, error) {
	r.calls++
	r.query = q
	return r.rows, nil
}

func TestRemainingIndependentRelatedHistoryBudgets(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"event-cap", "byte-cap", "exclusion-cap", "primary-partial", "remaining-sentinel"} {
		t.Run(kind, func(t *testing.T) {
			c := EvidenceCollection{Options: EvidenceQueryOptions{MaxEvents: 3, Lookback: 30 * 24 * time.Hour}, Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Second)}, Snapshot: EvidenceSnapshot{Sources: []string{"current"}}, MatchAddresses: []string{"192.0.2.1"}, MatchIOCs: []domain.IOC{{Type: "ip", Value: "203.0.113.2"}}, HistoryCandidates: []domain.Event{{EventID: "primary", Context: "{}"}}}
			r := &remainingIndependentHistoryReader{}
			switch kind {
			case "event-cap":
				c.Options.MaxEvents = 1
			case "byte-cap":
				c.HistoryCandidates[0].Context = strings.Repeat("x", 4<<20)
			case "exclusion-cap":
				for i := 0; i < 256; i++ {
					c.Snapshot.Sources = append(c.Snapshot.Sources, strings.Repeat("x", i+1))
				}
			case "primary-partial":
				c.HistoryTruncated = true
			case "remaining-sentinel":
				c.Options.MaxEvents = 2
				r.rows = []domain.Event{{EventID: "related", Context: "{}", CreatedAt: at.Add(-time.Hour)}, {EventID: "sentinel", Context: "{}", CreatedAt: at.Add(-2 * time.Hour)}}
			}
			a := EvidenceSupplyAudit{}
			if err := collectProviderRelatedHistory(context.Background(), r, &c, &a); err != nil {
				t.Fatal(err)
			}
			if !c.RelatedHistoryTruncated || len(a.Queries) != 1 {
				t.Fatal("budget exhaustion was hidden", c.RelatedHistoryTruncated, a.Queries)
			}
			if kind == "remaining-sentinel" {
				if r.calls != 1 || !r.query.SummaryOnly || r.query.RequireAssetIOC || len(c.RelatedHistoryCandidates) != 1 || len(c.HistoryCandidates)+len(c.RelatedHistoryCandidates) > c.Options.MaxEvents {
					t.Fatal("related summaries exceeded shared event cap or queried wrong relation", r.query, c.RelatedHistoryCandidates)
				}
			} else if r.calls != 0 || a.Queries[0].Status != "unavailable" {
				t.Fatal("exhausted budget still accessed the platform", r.calls, a.Queries)
			}
		})
	}
}

func TestRemainingIndependentRelatedHistoryRejectsUnboundRecords(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	for _, kind := range []string{"valid", "unknown-owner", "undeclared-ioc", "wrong-endpoint", "missing-device", "outside-window"} {
		t.Run(kind, func(t *testing.T) {
			when := at.Add(-time.Hour)
			m := map[string]any{"src_ip": "192.0.2.2", "dst_ip": "203.0.113.2", "device_id": "node-b", "first_time": when.Format(time.RFC3339Nano), "last_time": when.Format(time.RFC3339Nano), "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "203.0.113.2"}}
			switch kind {
			case "unknown-owner":
				m["src_ip"] = "192.0.2.99"
			case "undeclared-ioc":
				delete(m, "ioc")
			case "wrong-endpoint":
				m["dst_ip"] = "203.0.113.99"
			case "missing-device":
				m["device_id"] = ""
			case "outside-window":
				m["first_time"] = at.Format(time.RFC3339Nano)
				m["last_time"] = at.Format(time.RFC3339Nano)
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			c := EvidenceCollection{Snapshot: EvidenceSnapshot{Sources: []string{"current"}}, Assets: []domain.Asset{{ID: "asset-b", Address: "192.0.2.2", Status: 1}}, MatchAddresses: []string{"192.0.2.1"}, MatchIOCs: []domain.IOC{{Type: "ip", Value: "203.0.113.2"}}, RelatedHistoryCandidates: []domain.Event{{EventID: "historical", Context: string(raw)}}}
			rows := assembleProviderRelatedHistory(c, ReportHistory{Start: at.Add(-24 * time.Hour), End: at})
			want := 0
			if kind == "valid" {
				want = 1
			}
			if len(rows) != want {
				t.Fatal("unbound related history became evidence", kind, rows)
			}
		})
	}
}

func TestRemainingIndependentRSTRequiresTerminalProof(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	m := phaseOneWire(t, at, 100, nil, false, false)
	raw := nestedMap(m, "raw_packet")
	frame, err := hex.DecodeString(asString(raw["packet_hex"]))
	if err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	tcp.RST = true
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, tcp); err != nil {
		t.Fatal(err)
	}
	raw["packet_hex"] = hex.EncodeToString(buffer.Bytes())
	raw["captured_length"], raw["wire_length"] = len(buffer.Bytes()), len(buffer.Bytes())
	phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{m})
	bundle, _, err := PrepareEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	foundRST := false
	for _, input := range bundle.Inputs.Request.Inputs {
		if input.Network == nil {
			continue
		}
		for _, c := range input.Network.Connections {
			foundRST = foundRST || c.TCPState == "RST"
			if c.OutcomeVerified {
				t.Fatal("one captured RST invented a verified terminal outcome")
			}
		}
	}
	if !foundRST {
		t.Fatal("captured TCP reset was lost rather than retained as a packet state")
	}
}

func TestRemainingIndependentInfrastructureHistoryAcrossOwners(t *testing.T) {
	for _, device := range []string{"node-a", "other-observing-sensor"} {
		t.Run(device, func(t *testing.T) { remainingIndependentInfrastructureHistoryAcrossOwners(t, device) })
	}
}

func remainingIndependentInfrastructureHistoryAcrossOwners(t *testing.T, previousSensor string) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	if _, err := s.Store.CreateAsset(domain.Asset{ID: "asset-b", Address: "192.0.2.2", Status: 1}); err != nil {
		t.Fatal(err)
	}
	phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{providerTemporalMessage(t, at, 100)})
	// These are stored event summaries only. No historical packet or published
	// snapshot is needed to establish that these saved associations occurred.
	for _, row := range []struct {
		id, address, device string
		day                 int
	}{
		{"past-a", "192.0.2.1", previousSensor, 1},
		{"past-b", "192.0.2.2", "node-b", 2},
	} {
		when := at.AddDate(0, 0, -row.day)
		value, err := json.Marshal(map[string]any{"src_ip": row.address, "dst_ip": "203.0.113.2", "device_id": row.device, "first_time": when.Format(time.RFC3339Nano), "last_time": when.Format(time.RFC3339Nano), "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "203.0.113.2"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Store.CreateEvent(domain.Event{EventID: row.id, Context: string(value), CreatedAt: when, LastSeenAt: &when}); err != nil {
			t.Fatal(err)
		}
	}
	collection, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.HistorySnapshots) != 0 {
		t.Fatal("event association history expanded into packets")
	}
	bundle, _, err := PreprocessCollectedEvidence(context.Background(), collection)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Inputs.Manifest.PhaseOne.CurrentContacts) != 1 {
		t.Fatal("cross-owner history changed current independent contacts")
	}
	wantPrimary, wantOccurrenceSamples, wantRecurrence := 1, 2, float64(1)
	if previousSensor != "node-a" {
		wantPrimary, wantOccurrenceSamples, wantRecurrence = 0, 1, 0
	}
	if len(bundle.History.Rows) != wantPrimary {
		t.Fatal("related infrastructure data entered the primary temporal history", len(bundle.History.Rows), wantPrimary)
	}
	result, err := ExecutePreparedEvidence(context.Background(), bundle, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	seenInfra, seenDaily, seenDays, seenRecurrence := false, false, false, false
	for _, finding := range result.Evaluation.Result.Findings {
		if finding.Scope.AssetID != "asset-a" || finding.Scope.DeviceID != "node-a" || finding.Scope.EndpointID != "tcp://203.0.113.2:80" {
			continue
		}
		switch finding.FactID {
		case "F_HIST_INFRA_PERSISTENCE":
			seenInfra = true
			if finding.Status != evidence.Observed {
				t.Fatalf("two owners on consecutive historical days must remain usable local-positive evidence: %+v", finding)
			}
			if finding.Quality != "partial" {
				t.Fatal("saved associations became whole-network history coverage", finding.Quality)
			}
		case "F_FIXED_DAILY_WINDOW":
			seenDaily = true
			if finding.Measurements.SampleCount != wantOccurrenceSamples {
				t.Fatal("related associations entered fixed-daily samples", finding)
			}
		case "F_MULTI_DAY_PERSIST":
			seenDays = true
			if finding.Measurements.DaysActive == nil || *finding.Measurements.DaysActive != wantOccurrenceSamples {
				t.Fatal("related associations entered active-day samples", finding)
			}
		case "F_HIST_ASSET_IOC_RECURRENCE":
			seenRecurrence = true
			if finding.Measurements.Values["independent_events"] != wantRecurrence {
				t.Fatal("related foreign-device associations entered same-device recurrence", finding)
			}
		}
	}
	if !seenInfra || !seenDaily || !seenDays || !seenRecurrence {
		t.Fatalf("missing scoped regression results: infra=%v daily=%v days=%v recurrence=%v", seenInfra, seenDaily, seenDays, seenRecurrence)
	}
}

// These independent checks exercise source records through both layers. They
// deliberately do not derive expected counts from the implementation counters.
func TestRemainingIndependentPeerParseAccounting(t *testing.T) {
	for _, kind := range []string{"http", "dns"} {
		t.Run(kind, func(t *testing.T) {
			s := phaseOneFixture(t)
			at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
			phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{
				providerTemporalMessage(t, at, 10),
				providerTemporalMessage(t, at.Add(time.Minute), 200),
			})
			peer := providerTemporalMessage(t, at.Add(30*time.Second), 400)
			wantHTTP, wantDNS := int64(3), int64(0)
			if kind == "dns" {
				name, err := dnsmessage.NewName("agent.test.")
				if err != nil {
					t.Fatal(err)
				}
				message := dnsmessage.Message{Header: dnsmessage.Header{ID: 3}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
				payload, err := message.Pack()
				if err != nil {
					t.Fatal(err)
				}
				peer = phaseOneWire(t, at.Add(30*time.Second), 400, payload, true, false)
				wantHTTP, wantDNS = 2, 1
			}
			phaseOneInstallSnapshot(t, s, "peer", 1, []map[string]any{peer})
			collection, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(collection.Peers) != 1 {
				t.Fatalf("expected exactly one saved peer, got %d", len(collection.Peers))
			}
			inputDigest := digest(collection)
			bundle, _, err := PreprocessCollectedEvidence(context.Background(), collection)
			if err != nil {
				t.Fatal(err)
			}
			manifest := bundle.Inputs.Manifest
			if manifest.LoadedHits != 3 || manifest.WireFrameDecodeCount != 3 || manifest.HTTPRequestParseCount != wantHTTP || manifest.DNSMessageParseCount != wantDNS {
				t.Fatalf("3 saved wire sources must include peer parsing: hits=%d wire=%d HTTP=%d DNS=%d; want HTTP=%d DNS=%d", manifest.LoadedHits, manifest.WireFrameDecodeCount, manifest.HTTPRequestParseCount, manifest.DNSMessageParseCount, wantHTTP, wantDNS)
			}
			if digest(collection) != inputDigest {
				t.Fatal("offline preprocessing mutated frozen sources")
			}
		})
	}
}

func TestRemainingIndependentTemporalAssumptionDoesNotVerifyProtocols(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	m := providerTemporalMessage(t, at, 100)
	// Saved labels cannot prove a session's terminal outcome or response.
	m["tcp_state"], m["connection_state"], m["outcome"] = "RST", "CLOSED", "failure"
	m["outcome_verified"], m["complete"] = true, true
	nestedMap(m, "app")["http_status"] = 200
	nestedMap(m, "app")["response_verified"] = true
	phaseOneInstallSnapshot(t, s, "current", 1, []map[string]any{m})
	bundle, _, err := PrepareEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Inputs.Request.Quality.Coverage != evidence.CoveragePartial {
		t.Fatal("temporal assumption became global completeness")
	}
	connections, requests := 0, 0
	for _, input := range bundle.Inputs.Request.Inputs {
		if input.Network != nil {
			connections += len(input.Network.Connections)
			if input.Network.Complete {
				t.Fatal("saved packet or state labels proved complete network window")
			}
			for _, connection := range input.Network.Connections {
				if connection.OutcomeVerified {
					t.Fatal("unverified summary labels invented terminal outcome")
				}
			}
		}
		if input.HTTP != nil {
			requests += len(input.HTTP.Records)
			if input.HTTP.Complete {
				t.Fatal("temporal assumption became HTTP coverage proof")
			}
			for _, record := range input.HTTP.Records {
				if record.ResponseVerified {
					t.Fatal("unbound status label invented verified HTTP response")
				}
			}
		}
	}
	if connections != 1 || requests != 1 {
		t.Fatalf("valid request material was discarded instead of preserving unknown outcomes: connections=%d requests=%d", connections, requests)
	}
}

func TestRemainingIndependentSemanticCompositeCatalog(t *testing.T) {
	keys, ids := map[string]bool{}, map[string]int{}
	for _, definition := range evidence.SemanticDefinitions() {
		key := definition.Key.String()
		if keys[key] {
			t.Fatalf("duplicate semantic identity %s", key)
		}
		keys[key], ids[definition.Key.ID] = true, ids[definition.Key.ID]+1
	}
	if len(keys) != 23 || len(ids) != 21 || ids["S12"] != 2 || ids["S13"] != 2 {
		t.Fatalf("semantic composite identities collapsed: slots=%d IDs=%d S12=%d S13=%d", len(keys), len(ids), ids["S12"], ids["S13"])
	}
	for _, key := range []string{"S12/c2.domain_lexical/dga_lexical", "S12/phishing.deception/brand_semantic_impostor", "S13/payload.decoded_intent/command", "S13/payload.decoded_intent/other"} {
		if !keys[key] {
			t.Fatalf("missing independently reviewed slot %s", key)
		}
	}
	if _, err := providerOptions(providerTestOptions(t)); err != nil {
		t.Fatal("provider rejected the complete composite-key contract", err)
	}
}
