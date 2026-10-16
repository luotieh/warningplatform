package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func phaseOneFixture(t *testing.T) Services {
	t.Helper()
	s := Services{Store: store.NewMemoryStore()}
	_, err := s.Store.CreateAsset(domain.Asset{ID: "asset-a", Address: "192.0.2.1", Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type phaseOneReadOnlyStore struct {
	store.Store
	writes int
}

func (s *phaseOneReadOnlyStore) PutAggregateRecord(context.Context, store.AggregateRecord) error {
	s.writes++
	return fmt.Errorf("read-only test store")
}

func TestPhaseOneReadOnlyAndWireMismatch(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	m := phaseOneWire(t, at, 10, phaseOneHTTP("cmd=id"), false, false)
	m["ioc_value"] = "198.51.100.99"
	snap := phaseOneInstallSnapshot(t, s, "wrong-ioc", 1, []map[string]any{m})
	ro := &phaseOneReadOnlyStore{Store: s.Store}
	s.Store = ro
	s.SemanticModel = reportSemanticModelFunc(func(context.Context, evidence.SemanticCall) (string, error) {
		t.Fatal("read-only invoked model")
		return "", nil
	})
	p := phaseOneRun(t, s, snap, false)
	if ro.writes != 0 || p.Evidence.PhaseOne.Result.Score != 0 || p.Evidence.PhaseOne.Materials.Bindings[0].Verified {
		t.Fatal("read-only or wire-binding violation", ro.writes, p.Evidence.PhaseOne.Result)
	}
}

// Opt-in network integration; all report/cache writes are confined to MemoryStore.
// The endpoint is a separately started localhost proxy, never a production API.
func TestPhaseOneModelIsolated(t *testing.T) {
	endpoint := os.Getenv("PHASE_ONE_MODEL_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PHASE_ONE_MODEL_ENDPOINT for isolated model integration")
	}
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("integration endpoint must be localhost")
	}
	s := phaseOneFixture(t)
	s.LLM = &client.LLMClient{BaseURL: endpoint, Model: "K2.7", DisableThinking: true, HTTP: &http.Client{Timeout: 180 * time.Second}}
	calls := []map[string]any{}
	model := client.EvidenceSemanticModel{Client: *s.LLM}
	transport := reportSemanticModelFunc(func(ctx context.Context, call evidence.SemanticCall) (string, error) {
		response, err := model.Complete(ctx, call)
		calls = append(calls, map[string]any{"call": call, "response": response})
		return response, err
	})
	s.SemanticModel = transport
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	snap := phaseOneInstallSnapshot(t, s, "model-isolated-http", 1, []map[string]any{phaseOneWire(t, at, 100, phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false)})
	p := phaseOneRun(t, s, snap, true)
	dnsService := phaseOneFixture(t)
	dnsService.LLM = s.LLM
	dnsService.SemanticModel = transport
	name, err := dnsmessage.NewName("636174202f6574632f706173737764.agent.test.")
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	payload, err := dns.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dnsSnap := phaseOneInstallSnapshot(t, dnsService, "model-isolated-dns", 1, []map[string]any{phaseOneWire(t, at, 10, payload, true, false)})
	dnsResult := phaseOneRun(t, dnsService, dnsSnap, true)
	if path := os.Getenv("PHASE_ONE_MODEL_OUTPUT"); path != "" {
		b, _ := json.MarshalIndent(map[string]any{"model": "K2.7", "http": map[string]any{"phase_one": p.Evidence.PhaseOne, "semantics": p.Semantics}, "dns": map[string]any{"phase_one": dnsResult.Evidence.PhaseOne, "semantics": dnsResult.Semantics}, "calls": calls}, "", "  ")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if p.Semantics.Result == nil || p.Semantics.Result.Calls == 0 || len(p.Semantics.Result.Findings) == 0 {
		t.Fatal("model produced no validated semantic findings", p.Semantics.Status, p.Semantics.Reason)
	}
	if phaseOneUnit(t, p, "C05").Status != "observed" || phaseOneUnit(t, dnsResult, "C07").Status != "observed" {
		t.Fatal("model joint chain incomplete; inspect HTTP/DNS output")
	}
}

func phaseOneWire(t *testing.T, at time.Time, seq uint32, payload []byte, udp bool, syn bool) map[string]any {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("203.0.113.2"), Protocol: layers.IPProtocolTCP}
	var transport gopacket.SerializableLayer
	proto, port := "tcp", 80
	if udp {
		ip.Protocol = layers.IPProtocolUDP
		u := &layers.UDP{SrcPort: 45000, DstPort: 53}
		_ = u.SetNetworkLayerForChecksum(ip)
		transport = u
		proto, port = "udp", 53
	} else {
		tcp := &layers.TCP{SrcPort: 45000, DstPort: 80, Seq: seq, ACK: !syn, SYN: syn, Window: 8192}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		transport = tcp
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	return map[string]any{"device_id": "node-a", "src_ip": "192.0.2.1", "dst_ip": "203.0.113.2", "src_port": 45000, "dst_port": port, "protocol": proto, "event_time": at.UnixMicro(), "ioc_type": "ip", "ioc_value": "203.0.113.2", "ioc_source": "upstream", "session_id": "session", "transaction_id": fmt.Sprintf("tx-%d", seq), "packets": 1, "raw_packet": map[string]any{"packet_hex": hex.EncodeToString(raw), "capture_time": at.Format(time.RFC3339Nano), "capture_time_usec": at.UnixMicro(), "captured_length": len(raw), "wire_length": len(raw), "capture_truncated": false}}
}
func phaseOneInstallSnapshot(t *testing.T, s Services, id string, version int64, messages []map[string]any) EvidenceSnapshot {
	t.Helper()
	ctx := context.Background()
	snap := EvidenceSnapshot{EventID: id, Version: version, Sources: []string{id}, Count: int64(len(messages)), Context: map[string]any{}, Manifest: map[string]any{}}
	var first, last time.Time
	for i, m := range messages {
		at, err := time.Parse(time.RFC3339Nano, asString(nestedMap(m, "raw_packet")["capture_time"]))
		if err != nil {
			t.Fatal(err)
		}
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if last.IsZero() || at.After(last) {
			last = at
		}
		raw, _ := json.Marshal(m)
		h, err := s.Store.InsertHit(ctx, store.Hit{ID: fmt.Sprintf("%s-hit-%d", id, i), DedupKey: fmt.Sprintf("%s-hit-%d", id, i), EventID: id, OccurredAt: at, Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		if h.Sequence > snap.Watermark {
			snap.Watermark = h.Sequence
		}
		snap.Evidence = append(snap.Evidence, m)
	}
	for k, v := range messages[0] {
		snap.Context[k] = v
	}
	snap.Context["first_time"], snap.Context["last_time"] = first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano)
	snap.Context["ioc"] = map[string]any{"ioc_type": messages[0]["ioc_type"], "ioc_value": messages[0]["ioc_value"]}
	raw, _ := json.Marshal(snap.Context)
	_, err := s.Store.CreateEvent(domain.Event{EventID: id, Context: string(raw), CreatedAt: first, LastSeenAt: &last})
	if err != nil {
		t.Fatal(err)
	}
	if err := putRecord(ctx, s.Store, "snapshot", snapshotKey(id, version), id, snap); err != nil {
		t.Fatal(err)
	}
	if err := putRecord(ctx, s.Store, "segment", id, id, EventSegment{EventID: id, Published: version, Version: version, Sources: snap.Sources, Watermark: snap.Watermark, Count: snap.Count}); err != nil {
		t.Fatal(err)
	}
	return snap
}
func phaseOneHTTP(body string) []byte {
	return []byte(fmt.Sprintf("POST /agent HTTP/1.1\r\nHost: agent.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
}
func phaseOneRun(t *testing.T, s Services, snap EvidenceSnapshot, persist bool) preparedReportInput {
	t.Helper()
	event, _ := s.Store.GetEvent(snap.EventID)
	p, err := s.prepareReportInputMode(context.Background(), event, persist)
	if err != nil {
		t.Fatal(err)
	}
	if p.Evidence.PhaseOne == nil {
		t.Fatal("formal phase-one chain absent")
	}
	return p
}
func phaseOneUnit(t *testing.T, p preparedReportInput, id string) evidence.PhaseOneUnit {
	t.Helper()
	for _, u := range p.Evidence.PhaseOne.Result.Units {
		if u.ID == id {
			return u
		}
	}
	t.Fatal("unit absent", id)
	return evidence.PhaseOneUnit{}
}

func TestPhaseOneHTTPChainAndCache(t *testing.T) {
	s := phaseOneFixture(t)
	base := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 6; i++ {
		messages = append(messages, phaseOneWire(t, base.Add(time.Duration(i)*time.Minute), uint32(1000+i*500), phaseOneHTTP("cmd=636174202f6574632f706173737764"), false, false))
		messages = append(messages, phaseOneWire(t, base.Add(time.Duration(i)*time.Minute+time.Millisecond), uint32(5000+i), nil, false, false))
	}
	snap := phaseOneInstallSnapshot(t, s, "http-controlled", 1, messages)
	calls := 0
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		calls++
		return acceptedSemanticResponse(t, c), nil
	})
	p := phaseOneRun(t, s, snap, true)
	if u := phaseOneUnit(t, p, "C04"); u.Status != "observed" || u.Fact.Measurements.Values["max_repeated_endpoint_count"] != 6 {
		t.Fatal("ACK denominator or incomplete request", u)
	}
	if phaseOneUnit(t, p, "C05").Status != "observed" || phaseOneUnit(t, p, "C06").Status != "observed" {
		t.Fatal("semantic join absent", p.Evidence.PhaseOne.Result)
	}
	if calls == 0 {
		t.Fatal("S was not executed")
	}
	before := calls
	p2 := phaseOneRun(t, s, snap, true)
	if calls != before || !p2.Semantics.CacheHit || !p2.Evidence.PhaseOne.CacheHit {
		t.Fatal("versioned cache not reused", calls, before, p2.Semantics.CacheHit, p2.Evidence.PhaseOne.CacheHit)
	}
	if p.Evidence.PhaseOne.Result.Score != 35 {
		t.Fatal("same raw command/exploit counted twice", p.Evidence.PhaseOne.Result)
	}
	// Cached scores are re-derived; a matching key cannot bless tampering.
	record, exists, err := s.Store.AggregateRecord(context.Background(), "phase_one_result", p2.Evidence.PhaseOne.CacheKey)
	if err != nil || !exists {
		t.Fatal("phase cache missing", err)
	}
	var altered PhaseOneEvaluation
	if err = json.Unmarshal(record.Value, &altered); err != nil {
		t.Fatal(err)
	}
	altered.Result.Score = 99
	record.Value, _ = json.Marshal(altered)
	if err = s.Store.PutAggregateRecord(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	repaired := phaseOneRun(t, s, snap, true)
	if repaired.Evidence.PhaseOne.CacheHit || repaired.Evidence.PhaseOne.Result.Score != 35 {
		t.Fatal("corrupted joint cache accepted")
	}
	s.PhaseOnePolicy = &evidence.PhaseOneConfig{Version: "changed", MaxScore: 100, Points: map[string]int{"C01": 10, "C02": 15, "C03": 10, "C04": 16, "C05": 20, "C06": 20, "C07": 20}}
	p3 := phaseOneRun(t, s, snap, true)
	if p3.Evidence.PhaseOne.CacheKey == p2.Evidence.PhaseOne.CacheKey || p3.Evidence.PhaseOne.Result.Score != 36 {
		t.Fatal("policy cache not invalidated")
	}
}

func TestPhaseOneHTTPQueryAndContactBasis(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	request := []byte("GET /run?cmd=cat%20/etc/passwd HTTP/1.1\r\nHost: agent.test\r\n\r\n")
	messages := []map[string]any{phaseOneWire(t, at, 10, nil, false, true), phaseOneWire(t, at.Add(time.Second), 11, request, false, false)}
	snap := phaseOneInstallSnapshot(t, s, "query-command", 1, messages)
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, c), nil
	})
	p := phaseOneRun(t, s, snap, true)
	if phaseOneUnit(t, p, "C06").Status != "observed" {
		t.Fatal("query payload did not reach S09", p.Semantics)
	}
	if len(p.Evidence.PhaseOne.Materials.Contacts) != 1 || p.Evidence.PhaseOne.Materials.Contacts[0].Kind != "complete_http_request" || len(p.Evidence.PhaseOne.Materials.ScopeIncomplete) == 0 {
		t.Fatal("SYN/request inflated contacts or coverage")
	}
}

func TestPhaseOneIndependentJitterAndAcrossSnapshots(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	messages := []map[string]any{}
	for i := 0; i < 33; i++ {
		messages = append(messages, phaseOneWire(t, at, uint32(1000+i*500), nil, false, true))
		delta := 60 + 20*math.Cos(float64(i)*2*math.Pi/8)
		at = at.Add(time.Duration(delta*1e6) * time.Microsecond)
	}
	snap := phaseOneInstallSnapshot(t, s, "jitter-controlled", 1, messages)
	p := phaseOneRun(t, s, snap, false)
	if u := phaseOneUnit(t, p, "C02"); u.Status != "observed" || u.Fact.Measurements.SampleCount != 33 {
		t.Fatal("independent jitter did not reuse F", u)
	}
	s = phaseOneFixture(t)
	base := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	phaseOneInstallSnapshot(t, s, "day-2", 3, []map[string]any{phaseOneWire(t, base.Add(-48*time.Hour), 10, nil, false, true)})
	phaseOneInstallSnapshot(t, s, "day-1", 7, []map[string]any{phaseOneWire(t, base.Add(-24*time.Hour), 20, nil, false, true)})
	snap = phaseOneInstallSnapshot(t, s, "day0", 11, []map[string]any{phaseOneWire(t, base, 30, nil, false, true)})
	p = phaseOneRun(t, s, snap, false)
	if u := phaseOneUnit(t, p, "C03"); u.Status != "observed" {
		t.Fatal("cross-snapshot daily window", u, p.Evidence.PhaseOne.Materials)
	}
	if len(p.Evidence.PhaseOne.Materials.Sources) != 3 || len(p.Evidence.PhaseOne.Materials.Contacts) != 3 {
		t.Fatal("missing source manifests", p.Evidence.PhaseOne.Materials)
	}
	// Packet retries at a later time with the same SYN sequence cannot add a contact.
	m := p.Evidence.PhaseOne.Materials
	m.Contacts = append(m.Contacts, m.Contacts[0])
	m = dedupPhaseOneContacts(m)
	if len(m.Contacts) != 3 || m.DuplicateContacts != 1 {
		t.Fatal("retry inflated contacts")
	}
}

func TestPhaseOneDNSChainAndTLSDoesNotBecomeHTTP(t *testing.T) {
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 12, 4, 0, 0, 0, time.UTC)
	q := "636174202f6574632f706173737764.agent.test."
	name, err := dnsmessage.NewName(q)
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	payload, _ := message.Pack()
	m := phaseOneWire(t, at, 10, payload, true, false)
	m["app"] = map[string]any{"dns_query": strings.TrimSuffix(q, ".")}
	snap := phaseOneInstallSnapshot(t, s, "dns-controlled", 1, []map[string]any{m})
	s.SemanticModel = reportSemanticModelFunc(func(_ context.Context, c evidence.SemanticCall) (string, error) {
		return acceptedSemanticResponse(t, c), nil
	})
	p := phaseOneRun(t, s, snap, true)
	if u := phaseOneUnit(t, p, "C07"); u.Status != "observed" || u.Score != 20 {
		t.Fatal("DNS hard/semantic chain", u, p.Semantics)
	}
	foundDNS := false
	for _, task := range p.Semantics.Result.Plan.Tasks {
		if task.Slot.Key.ID == "S04" {
			foundDNS = true
		}
	}
	if !foundDNS || p.Evidence.Pipeline == nil || len(p.Evidence.Pipeline.Checks) != 82 {
		t.Fatal("full registry or DNS slot missing")
	}
	s = phaseOneFixture(t)
	snap = phaseOneInstallSnapshot(t, s, "tls-controlled", 1, []map[string]any{phaseOneWire(t, at, 10, []byte{23, 3, 3, 0, 4, 0, 1, 2, 3}, false, false)})
	p = phaseOneRun(t, s, snap, true)
	for _, id := range []string{"C04", "C05", "C06", "C07"} {
		if phaseOneUnit(t, p, id).Status == "observed" {
			t.Fatal("TLS inferred plaintext", id)
		}
	}
}

// Reads the saved real event/history only. No SSH, model or production writes.
func TestPhaseOneArchivedSnapshot34C01(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	var archived struct {
		Snapshot EvidenceSnapshot `json:"snapshot"`
		Hits     []struct {
			ID  string          `json:"hit_id"`
			Raw json.RawMessage `json:"effective_raw"`
		} `json:"hits"`
	}
	read := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join(root, "docs", name))
		if os.IsNotExist(err) {
			t.Skip("archived acceptance input not installed: " + name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	read("180单事件一期输入材料-2026-10-15.json", &archived)
	var acceptance struct {
		Recurrence struct {
			Records []map[string]any `json:"records"`
		} `json:"recurrence"`
	}
	read("第一轮验收-180-快照34-2026-10-15.json", &acceptance)
	if len(acceptance.Recurrence.Records) != 85 {
		t.Fatal("archived history changed")
	}
	s := Services{Store: store.NewMemoryStore()}
	_, _ = s.Store.CreateAsset(domain.Asset{ID: "asset-0f4ef4d8ee0aa302", Address: "180.104.100.118", Status: 1})
	ctx := context.Background()
	snap := archived.Snapshot
	for _, hit := range archived.Hits {
		m := map[string]any{}
		_ = json.Unmarshal(hit.Raw, &m)
		at, _ := time.Parse(time.RFC3339Nano, asString(nestedMap(m, "raw_packet")["capture_time"]))
		if _, err := s.Store.InsertHit(ctx, store.Hit{ID: hit.ID, DedupKey: hit.ID, EventID: snap.EventID, OccurredAt: at, Raw: hit.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(snap.Context)
	first, _ := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	last, _ := time.Parse(time.RFC3339Nano, asString(snap.Context["last_time"]))
	_, _ = s.Store.CreateEvent(domain.Event{EventID: snap.EventID, Context: string(raw), CreatedAt: first, LastSeenAt: &last})
	_ = putRecord(ctx, s.Store, "snapshot", snapshotKey(snap.EventID, 34), snap.EventID, snap)
	_ = putRecord(ctx, s.Store, "segment", snap.EventID, snap.EventID, EventSegment{EventID: snap.EventID, Published: 34})
	for _, row := range acceptance.Recurrence.Records {
		src, dst := firstNonEmpty(asString(row["src_ip"]), asString(row["source_address"])), firstNonEmpty(asString(row["dst_ip"]), asString(row["destination_address"]))
		c := map[string]any{"src_ip": src, "dst_ip": dst, "device_id": "node-arm-offline-001", "first_time": row["first_time"], "last_time": row["last_time"], "ioc": map[string]any{"ioc_type": "ip", "ioc_value": "104.21.57.117"}}
		b, _ := json.Marshal(c)
		at, _ := time.Parse(time.RFC3339Nano, asString(row["last_time"]))
		_, err := s.Store.CreateEvent(domain.Event{EventID: asString(row["event_id"]), Context: string(b), CreatedAt: at, LastSeenAt: &at})
		if err != nil {
			t.Fatal(err)
		}
	}
	p := phaseOneRun(t, s, snap, false)
	u := phaseOneUnit(t, p, "C01")
	if u.Status != "observed" || u.Score != 10 || u.Fact.Measurements.Values["independent_events"] != 85 || u.Fact.Measurements.Values["days_active"] != 22 {
		t.Fatal("real C01 replay", u)
	}
	if len(p.Evidence.PhaseOne.Materials.Bindings) != 14 || len(p.Evidence.PhaseOne.Materials.Contacts) != 0 {
		t.Fatal("TLS packet burst became communication counts", p.Evidence.PhaseOne.Materials)
	}
	if phaseOneUnit(t, p, "C02").Status != "missing" || phaseOneUnit(t, p, "C03").Status != "missing" {
		t.Fatal("raw14 inflated temporal facts")
	}
	export := os.Getenv("PHASE_ONE_ACCEPTANCE_OUTPUT")
	if export != "" {
		b, _ := json.MarshalIndent(p.Evidence.PhaseOne, "", "  ")
		if err := os.WriteFile(export, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPhaseOneOtherRealProtocolSamples(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", ".local")
	groups := map[string][]map[string]any{}
	for _, file := range []string{"phase1-v1-180-verify.json", "phase1-v1-180-supplement.json"} {
		b, err := os.ReadFile(filepath.Join(root, file))
		if os.IsNotExist(err) {
			t.Skip("optional real protocol archive not installed")
		}
		if err != nil {
			t.Fatal(err)
		}
		var saved struct {
			DNS []struct {
				Event string         `json:"event_id"`
				Raw   map[string]any `json:"raw"`
			} `json:"novel_protocol_samples"`
			HTTP []struct {
				Event string         `json:"event_id"`
				Raw   map[string]any `json:"raw"`
			} `json:"http_candidates_200k"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.UseNumber()
		if err = decoder.Decode(&saved); err != nil {
			t.Fatal(err)
		}
		for _, row := range saved.DNS {
			groups[row.Event] = append(groups[row.Event], row.Raw)
		}
		for _, row := range saved.HTTP {
			groups[row.Event] = append(groups[row.Event], row.Raw)
		}
	}
	keys := []string{}
	for id := range groups {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	outputs := map[string]any{}
	for _, id := range keys {
		t.Run(id, func(t *testing.T) {
			s := Services{Store: store.NewMemoryStore()}
			_, err := s.Store.CreateAsset(domain.Asset{ID: "real-asset-180", Address: "180.104.100.118", Status: 1})
			if err != nil {
				t.Fatal(err)
			}
			snap := phaseOneInstallSnapshot(t, s, id, 1, groups[id])
			p := phaseOneRun(t, s, snap, false)
			if p.Evidence.PhaseOne.Result.Score != 0 {
				t.Fatal("unproven real sample earned score", p.Evidence.PhaseOne.Result)
			}
			outputs[id] = map[string]any{"phase_one": p.Evidence.PhaseOne.Result, "raw_hits": len(groups[id]), "bindings": p.Evidence.PhaseOne.Materials.Bindings, "contacts": p.Evidence.PhaseOne.Materials.Contacts, "diagnostics": p.Evidence.PhaseOne.Materials.Diagnostics, "semantic_plan": p.Semantics}
			t.Logf("real hits=%d contacts=%d C04=%s C07=%s", len(groups[id]), len(p.Evidence.PhaseOne.Materials.Contacts), phaseOneUnit(t, p, "C04").Status, phaseOneUnit(t, p, "C07").Status)
		})
	}
	if path := os.Getenv("PHASE_ONE_REAL_OUTPUT"); path != "" {
		b, _ := json.MarshalIndent(outputs, "", "  ")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
