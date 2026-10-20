// Package mockscenario is an offline acceptance tool. It produces formal L2
// bundles, never verdicts, and delegates all F/S/C calculations to service.
package mockscenario

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
)

const Version = "synthetic-composite-scenarios-1"

type Scenario struct {
	ID         string                         `json:"scenario_id"`
	Directory  string                         `json:"directory"`
	Title      string                         `json:"title"`
	Background string                         `json:"background"`
	Boundary   string                         `json:"boundary"`
	Bundle     service.PreparedEvidenceBundle `json:"-"`
	Sources    map[string]any                 `json:"sources"`
	Timeline   []map[string]any               `json:"timeline"`
}

type builder struct {
	s    Scenario
	next int
}

func Build(template service.PreparedEvidenceBundle) ([]Scenario, error) {
	out := []Scenario{}
	for _, id := range []string{"c2", "botnet", "phishing", "network-activity"} {
		x := newBuilder(template, id)
		switch id {
		case "c2":
			x.c2()
		case "botnet":
			x.botnet()
		case "phishing":
			x.phishing()
		default:
			x.network()
		}
		x.finish()
		if err := x.s.Bundle.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, x.s)
	}
	return out, nil
}

func newBuilder(t service.PreparedEvidenceBundle, id string) *builder {
	// Copy only executable configuration from the checked-in official example.
	// No sample hits, conclusions, model responses or expected results survive.
	b := service.PreparedEvidenceBundle{SchemaVersion: t.SchemaVersion, PreprocessVersion: t.PreprocessVersion,
		FactConfig: t.FactConfig, SemanticOptions: service.DefaultReportSemanticOptions(), JointConfig: evidence.DefaultPhaseOneConfig()}
	b.SemanticOptions.ModelVersion = "controlled-composite-stub-v1-not-real-model"
	b.Event = domain.Event{EventID: "synthetic-" + id, EventName: "Synthetic Fixture: " + id}
	at := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	b.Snapshot = service.EvidenceSnapshot{EventID: b.Event.EventID, Version: 1, Watermark: 1, RevisionWatermark: 1, Sources: []string{b.Event.EventID}, Context: map[string]any{"scenario_id": id, "synthetic_fixture": true}, Manifest: map[string]any{}}
	b.Inputs.Request = evidence.Request{EventID: b.Event.EventID, SnapshotVersion: 1, Facts: evidence.SupportedFacts(), Quality: evidence.Quality{Coverage: evidence.CoverageComplete, CaptureTruncated: ptr(false), SavedTimelineComplete: ptr(true)}}
	b.Inputs.Manifest = service.SnapshotEvidenceManifest{AdapterVersion: "report-snapshot-adapter-2.1", SnapshotVersion: 1, Watermark: 1, RevisionWatermark: 1, Coverage: "complete",
		PhaseOne: &service.PhaseOneMaterials{Expanded: true, Complete: true, CurrentComplete: true, Diagnostics: []string{"Synthetic Fixture; verified means internally checked synthetic provenance only"}}}
	b.Inputs.HTTP = map[string]service.PreparedHTTPPayload{}
	b.Inputs.PlatformHistory = map[string]*evidence.HistoryData{}
	b.Inputs.SemanticMaterials = &evidence.SemanticRequest{InputMode: evidence.SemanticRaw, EventID: b.Event.EventID, SnapshotVersion: 1}
	b.History = service.ReportHistory{Version: Version, Status: "available", Start: at.AddDate(0, 0, -30), End: at, FrozenSnapshots: map[string]service.EvidenceSnapshot{}, ExactRelations: true}
	return &builder{s: Scenario{ID: id, Bundle: b, Sources: map[string]any{}, Boundary: "Synthetic Fixture；verified只表示内部关联；Stub只验证规划/执行/引用合同，不证明语义准确性、攻击成功或生产能力。"}}
}

func ptr[T any](v T) *T { return &v }
func prov(ids ...string) evidence.Provenance {
	return evidence.Provenance{Verified: true, Complete: true, Version: Version, SourceIDs: ids}
}
func scope(a, endpoint string) evidence.Scope {
	return evidence.Scope{AssetID: a, DeviceID: "sensor-" + a, EndpointID: endpoint}
}
func scopeKey(s evidence.Scope) string {
	return s.AssetID + "\x00" + s.EndpointID + "\x00" + s.DeviceID
}

func (x *builder) source(id string, data any) {
	x.s.Sources[id] = map[string]any{"synthetic_fixture": true, "data": data}
}
func (x *builder) hit(s evidence.Scope, at time.Time, kind string, data any) evidence.Hit {
	x.next++
	id := fmt.Sprintf("synthetic-%s-%04d-%s", x.s.ID, x.next, kind)
	h := evidence.Hit{ID: id, OccurredAt: at, Scope: s}
	x.s.Bundle.Inputs.Request.Hits = append(x.s.Bundle.Inputs.Request.Hits, h)
	x.source(id, map[string]any{"hit": h, "record": data})
	x.s.Timeline = append(x.s.Timeline, map[string]any{"time": at, "kind": kind, "source_id": id, "scope": s})
	return h
}
func (x *builder) asset(id, ip, role string) {
	// Use the existing public JSON shape for registry fields; no new input type.
	raw, _ := json.Marshal(map[string]any{"id": id, "address": ip, "name": "Synthetic " + id, "asset_type": role, "status": 1})
	var a domain.Asset
	_ = json.Unmarshal(raw, &a)
	a.CreatedAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a.UpdatedAt = x.s.Bundle.History.End
	x.s.Bundle.Assets = append(x.s.Bundle.Assets, a)
	x.source("registry-"+id, map[string]any{"asset_id": id, "device_id": "sensor-" + id, "ip": ip, "role": role})
}
func (x *builder) input(s evidence.Scope, start, end time.Time) *evidence.Input {
	return &evidence.Input{Scope: s, Window: &evidence.AnalysisWindow{Start: start, End: end}}
}
func (x *builder) addInput(i *evidence.Input) {
	x.s.Bundle.Inputs.Request.Inputs = append(x.s.Bundle.Inputs.Request.Inputs, *i)
}
func (x *builder) bind(h evidence.Hit, typ, value, field string) {
	p := x.s.Bundle.Inputs.Manifest.PhaseOne
	p.Bindings = append(p.Bindings, evidence.PhaseOneBinding{Scope: h.Scope, IOCType: typ, IOCValue: value, Field: field, SourceID: h.ID, Verified: true, Reason: "synthetic preprocessor field match"})
}
func (x *builder) contact(h evidence.Hit, typ, value, kind string) {
	p := x.s.Bundle.Inputs.Manifest.PhaseOne
	c := service.PhaseOneContact{ID: h.ID + ":" + kind, Kind: kind, HitID: h.ID, Time: h.OccurredAt, Scope: h.Scope, IOCType: typ, IOCValue: value, Snapshot: service.PhaseOneSnapshotSource{EventID: x.s.Bundle.Event.EventID, Version: 1, Watermark: 1, RevisionWatermark: 1, Complete: true}}
	p.Contacts = append(p.Contacts, c)
	p.CurrentContacts = append(p.CurrentContacts, c)
}
func (x *builder) dns(s evidence.Scope, at time.Time, domain, ip string, rcode int) evidence.DNSRecord {
	r := evidence.DNSRecord{Time: at, Domain: domain, RCode: rcode, RCodeKnown: true}
	if ip != "" {
		r.Answers = []string{ip}
	}
	h := x.hit(s, at, "dns", r)
	r.SourceID = h.ID
	x.bind(h, "domain", domain, "dns.question.name")
	x.contact(h, "domain", domain, "dns_question")
	x.s.Bundle.Inputs.Manifest.PhaseOne.Records = append(x.s.Bundle.Inputs.Manifest.PhaseOne.Records, service.PhaseOneRecord{Hit: h, DNS: &r, IOCType: "domain", IOCValue: domain})
	x.s.Bundle.Inputs.Observations = append(x.s.Bundle.Inputs.Observations, service.SnapshotSemanticObservation{HitID: h.ID, Scope: s, DNS: &r, Complete: true})
	x.source(h.ID, map[string]any{"hit": h, "dns": r})
	return r
}
func (x *builder) connection(s evidence.Scope, at time.Time, dst string, port uint16, state, app string, payload uint64, terminal bool) evidence.Connection {
	r := evidence.Connection{Time: at, AssetID: s.AssetID, Destination: dst, Port: port, Transport: "tcp", TCPState: state, OutcomeVerified: terminal, ProtocolParsed: app != "", AppProtocol: app, PayloadBytes: ptr(payload)}
	h := x.hit(s, at, "tcp", r)
	r.SourceID = h.ID
	r.SessionID = h.ID + ":session"
	x.bind(h, "ip", dst, "ip.destination")
	// Only a measured initiating operation enters the contact timeline; outcome
	// is separate and SYN_SENT remains pending in the network facts.
	x.contact(h, "ip", dst, "tcp_initiation")
	x.source(h.ID, map[string]any{"hit": h, "connection": r})
	return r
}
func (x *builder) http(s evidence.Scope, at time.Time, rawURL, method, body, response string) evidence.HTTPRecord {
	u, _ := url.Parse(rawURL)
	tx := fmt.Sprintf("synthetic-%s-tx-%04d", x.s.ID, x.next+1)
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: FixtureAgent/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: http://portal.test/\r\nContent-Length: %d\r\n\r\n%s", method, u.RequestURI(), u.Host, len(body), body)
	h := x.hit(s, at, "http", map[string]any{"raw_request": raw, "response": response})
	r := evidence.HTTPRecord{SourceID: h.ID, RequestID: tx + ":request", TransactionID: tx, SessionID: tx + ":session", Time: at, URL: rawURL, Method: method, UserAgent: "FixtureAgent/1.0", RawRequest: raw, ParsedBody: body, BodyLength: ptr(uint64(len(body))), Fields: map[string]string{}, ResponseURL: rawURL, ResponseStatus: 200, ResponseVerified: true}
	if parts := strings.Fields(response); len(parts) >= 2 {
		r.ResponseStatus, _ = strconv.Atoi(parts[1])
	}
	fields, _ := url.ParseQuery(body)
	for key, v := range fields {
		r.Fields[key] = v[0]
	}
	x.s.Bundle.Inputs.HTTP[h.ID] = service.PreparedHTTPPayload{Raw: raw, Body: body}
	x.bind(h, "domain", u.Hostname(), "http.request.host")
	x.contact(h, "domain", u.Hostname(), "complete_http_request")
	x.s.Bundle.Inputs.Manifest.PhaseOne.Records = append(x.s.Bundle.Inputs.Manifest.PhaseOne.Records, service.PhaseOneRecord{Hit: h, HTTP: &r, IOCType: "domain", IOCValue: u.Hostname(), HTTPCandidate: true, RawRequest: raw, ParsedBody: body})
	x.source(h.ID, map[string]any{"hit": h, "http": r, "raw_request": raw, "response": response})
	return r
}
func (x *builder) baseline(i *evidence.Input, id evidence.FactID, metrics map[string]float64, frequencies map[string]float64) {
	sid := "baseline-" + x.s.ID + "-" + i.Scope.AssetID + "-" + i.Scope.EndpointID + "-" + string(id)
	i.Baselines = append(i.Baselines, evidence.Baseline{Provenance: prov(sid), FactID: id, Metrics: metrics, Frequencies: frequencies})
	x.source(sid, map[string]any{"scope": i.Scope, "reference_window": "2026-09-01/2026-09-30, excludes incident", "cohort": "synthetic normal business cohort; stipulated reference distribution", "metrics": metrics, "frequencies": frequencies})
}
func (x *builder) subject(s evidence.Scope, w evidence.AnalysisWindow, id string) *evidence.SemanticSubject {
	return &evidence.SemanticSubject{ID: id, PropositionID: id, Scope: s, Window: w, InputMode: evidence.SemanticRaw}
}
func (x *builder) mat(s *evidence.SemanticSubject, kind, text string, ids ...string) int {
	m := evidence.SemanticMaterial{ID: s.ID + ":" + kind + fmt.Sprint(len(s.Materials)), Kind: kind, Scope: s.Scope, Window: s.Window, SnapshotVersion: 1, Text: text, FieldPath: "synthetic." + kind, Provenance: prov(ids...)}
	s.Materials = append(s.Materials, m)
	return len(s.Materials) - 1
}
func (x *builder) contextMaterials(s *evidence.SemanticSubject, source string) {
	x.mat(s, "visibility", "Synthetic complete observation within this fixture window only; not all enterprise traffic.", source)
	x.mat(s, "gaps", "No endpoint execution evidence, no adjudicated campaign identity, no production model evaluation.", source)
	x.mat(s, "asset_role", "Synthetic employee workstation", "registry-"+s.Scope.AssetID)
	x.mat(s, "task_context", "Legitimate monitoring/update automation is an alternative requiring business confirmation; no authorization inferred.", "registry-"+s.Scope.AssetID)
}
func (x *builder) httpSubject(i *evidence.Input, r evidence.HTTPRecord, response string, extra func(*evidence.SemanticSubject)) {
	s := x.subject(i.Scope, *i.Window, "operation:"+r.SourceID)
	a := x.mat(s, "protocol_request", r.RawRequest, r.SourceID)
	b := x.mat(s, "protocol_response", response, r.SourceID)
	s.Materials[a].TransactionID = r.TransactionID
	s.Materials[a].Direction = "outbound"
	s.Materials[a].Protocol = "http"
	s.Materials[a].Method = r.Method
	s.Materials[a].Destination = r.URL
	s.Materials[b].TransactionID = r.TransactionID
	s.Materials[b].Direction = "inbound"
	s.Materials[b].Protocol = "http"
	p := x.mat(s, "pair", "Verified synthetic request/response transaction", r.SourceID)
	s.Materials[p].RelatedIDs = []string{s.Materials[a].ID, s.Materials[b].ID}
	s.Materials[p].TransactionID = r.TransactionID
	d := x.mat(s, "direction", "outbound", r.SourceID)
	s.Materials[d].Direction = "outbound"
	s.Materials[d].TransactionID = r.TransactionID
	x.mat(s, "ua", r.UserAgent, r.SourceID)
	x.contextMaterials(s, r.SourceID)
	if extra != nil {
		extra(s)
	}
	for k := range s.Materials {
		if s.Materials[k].Kind == "parsed_payload" {
			s.Materials[k].TransactionID = r.TransactionID
		}
	}
	x.s.Bundle.Inputs.SemanticMaterials.Subjects = append(x.s.Bundle.Inputs.SemanticMaterials.Subjects, *s)
}
func (x *builder) decode(s *evidence.SemanticSubject, text, source string) {
	a := x.mat(s, "encoded_payload", base64.StdEncoding.EncodeToString([]byte(text)), source)
	b := x.mat(s, "decoded_payload", text, source)
	d := x.mat(s, "decode", "Code-verifiable base64 chain", source)
	s.Materials[d].DecodeSteps = []evidence.SemanticDecodeStep{{Encoding: "base64", InputID: s.Materials[a].ID, OutputID: s.Materials[b].ID}}
	op := x.mat(s, "operation_context", "Synthetic test operation only; no execution outcome", source)
	s.Materials[op].RelatedIDs = []string{s.Materials[b].ID}
	for k := range s.Materials {
		if s.Materials[k].Kind == "protocol_request" {
			s.Materials[k].RelatedIDs = append(s.Materials[k].RelatedIDs, s.Materials[b].ID)
			s.Materials[b].TransactionID = s.Materials[k].TransactionID
		}
	}
}

func (x *builder) c2() {
	x.s.Directory = "mock-01-c2-beacon"
	x.s.Title = "C2周期通信"
	x.s.Background = "员工终端连续五个自然日在北京时间09:00访问更新端点；当前日24个独立TCP联系与24次HTTP事务，报文中含无害命令测试标记。周期可能来自合法更新程序，未提供授权或主机执行证据。"
	x.asset("workstation-c2", "192.0.2.10", "workstation")
	at := x.s.Bundle.History.End
	end := at.Add(time.Hour)
	s := scope("workstation-c2", "tcp://198.51.100.20:8080")
	i := x.input(s, at, end)
	ds := scope(s.AssetID, "udp://192.0.2.53:53")
	di := x.input(ds, at.Add(-time.Minute), end)
	dr := x.dns(ds, at.Add(-10*time.Second), "updates-fixture.test", "198.51.100.20", 0)
	di.DNS = &evidence.DNSData{Provenance: prov(dr.SourceID), Records: []evidence.DNSRecord{dr}}
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nMOCK_COMMAND_REQUEST accepted for simulation; no command executed"
	for n := 0; n < 24; n++ {
		t := at.Add(time.Duration(n) * time.Minute)
		c := x.connection(s, t, "198.51.100.20", 8080, "ESTABLISHED", "http", 96, true)
		if i.Network == nil {
			i.Network = &evidence.NetworkData{Provenance: prov(c.SourceID), ServicesVerified: true, Services: []evidence.Service{{Port: 8080, Protocol: "http"}}}
		}
		i.Network.Connections = append(i.Network.Connections, c)
		r := x.http(s, t.Add(time.Second), "http://updates-fixture.test:8080/poll", "POST", "cmd="+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("MOCK_COMMAND_REQUEST collect_demo_status"))), response)
		if i.HTTP == nil {
			i.HTTP = &evidence.HTTPData{Provenance: prov(r.SourceID)}
		}
		i.HTTP.Records = append(i.HTTP.Records, r)
		i.HTTP.RequestCandidates++
	}
	p := x.s.Bundle.Inputs.Manifest.PhaseOne
	for day := 4; day >= 1; day-- {
		hid := fmt.Sprintf("synthetic-c2-history-day-%d", day)
		start := at.AddDate(0, 0, -day)
		ss := service.PhaseOneSnapshotSource{EventID: hid, Version: 1, Watermark: 24, RevisionWatermark: 1, LoadedHits: 24, Complete: true}
		p.Sources = append(p.Sources, ss)
		x.s.Bundle.History.FrozenSnapshots[hid] = service.EvidenceSnapshot{EventID: hid, Version: 1, Watermark: 24, RevisionWatermark: 1, Count: 24, Sources: []string{hid}, Context: map[string]any{"synthetic_fixture": true}}
		row := service.ReportHistoryRow{EventID: hid, DeviceID: s.DeviceID, AssetIDs: []string{s.AssetID}, AllAssetIDs: []string{s.AssetID}, IOCs: []domain.IOC{{Type: "domain", Value: "updates-fixture.test"}}, ActivityIOCs: []domain.IOC{{Type: "domain", Value: "updates-fixture.test"}}, First: start, Last: start.Add(23 * time.Minute), Relation: "same_asset_ioc", ActivityType: "http", DestinationAddress: "198.51.100.20"}
		x.s.Bundle.History.Rows = append(x.s.Bundle.History.Rows, row)
		x.source(hid, row)
		for n := 0; n < 24; n++ {
			id := fmt.Sprintf("%s-http-%02d", hid, n)
			c := service.PhaseOneContact{ID: id, HitID: id, Kind: "complete_http_request", Scope: s, IOCType: "domain", IOCValue: "updates-fixture.test", Time: start.Add(time.Duration(n) * time.Minute), Snapshot: ss}
			p.Contacts = append(p.Contacts, c)
			x.source(id, c)
		}
	}
	i.History = &evidence.HistoryData{Provenance: prov("synthetic-c2-history-day-1", "synthetic-c2-history-day-2", "synthetic-c2-history-day-3", "synthetic-c2-history-day-4"), PlatformRecords: true, AsOf: at, LookbackStart: at.AddDate(0, 0, -30), IOC: "updates-fixture.test", Endpoint: s.EndpointID}
	for _, row := range x.s.Bundle.History.Rows {
		i.History.Events = append(i.History.Events, evidence.HistoryEvent{ID: row.EventID, Time: row.First, AssetID: s.AssetID, IOC: "updates-fixture.test", Endpoint: s.EndpointID, Relation: "same_asset_ioc", ObservationKind: "application_contact"})
	}
	x.s.Bundle.Inputs.PlatformHistory[scopeKey(s)] = i.History
	x.baseline(i, "F_HTTP_UA_RARITY", map[string]float64{"ua_frequency": 0.10, "ua_frequency_p01": 0.005}, nil)
	x.baseline(i, "F_HTTP_SIZE_STABILITY", map[string]float64{"size_cv_p05": 0.05, "unique_size_ratio_p05": 0.1}, nil)
	x.httpSubject(i, i.HTTP.Records[0], response, func(sub *evidence.SemanticSubject) {
		x.decode(sub, "MOCK_COMMAND_REQUEST collect_demo_status", i.HTTP.Records[0].SourceID)
		x.mat(sub, "parsed_payload", i.HTTP.Records[0].ParsedBody, i.HTTP.Records[0].SourceID)
		x.mat(sub, "history", "Four previous days of same asset/domain activity; no malicious adjudication", "synthetic-c2-history-day-1")
		x.mat(sub, "current_pattern", "24 complete HTTP requests at one-minute intervals; no adjudicated intent", i.HTTP.Records[0].SourceID)
	})
	x.addInput(i)
	x.addInput(di)
	x.s.Bundle.Snapshot.Context["ioc"] = map[string]any{"ioc_type": "domain", "ioc_value": "updates-fixture.test", "source": "synthetic-intel-c2", "label": "mock suspicious only"}
	x.source("synthetic-intel-c2", x.s.Bundle.Snapshot.Context["ioc"])
}

func (x *builder) botnet() {
	x.s.Directory = "mock-02-botnet-coordination"
	x.s.Title = "Botnet多资产协同"
	x.s.Background = "三个不同员工终端在一小时观测窗内同步访问同一合成更新服务，每分钟一次、相差1至2秒；各自DNS成功和NXDOMAIN独立保存。公共端点和同步不证明感染；没有传播路径或已定谳战役历史。"
	at := x.s.Bundle.History.End
	end := at.Add(time.Hour)
	g := evidence.GroupInput{ID: "synthetic-update-cohort", Window: evidence.AnalysisWindow{Start: at, End: end}, Provenance: prov("synthetic-group-registry"), IOC: "pool-fixture.test", Endpoint: "tcp://198.51.100.30:8080", DNSOwnership: map[string]string{}}
	x.source("synthetic-group-registry", map[string]any{"members": []string{"bot-1", "bot-2", "bot-3"}, "basis": "synthetic asset registry observation cohort; not infected membership"})
	for a := 1; a <= 3; a++ {
		asset := fmt.Sprintf("bot-%d", a)
		x.asset(asset, fmt.Sprintf("192.0.2.%d", a+10), "workstation")
		s := scope(asset, g.Endpoint)
		i := x.input(s, at, end)
		i.Network = &evidence.NetworkData{Provenance: prov("synthetic-group-registry"), ServicesVerified: true, Services: []evidence.Service{{Port: 8080, Protocol: "http"}}}
		member := evidence.GroupMember{AssetID: asset, Scope: s, MembershipVerified: true, Subnet: "192.0.2.0/24", Role: "workstation", Addresses: []string{fmt.Sprintf("192.0.2.%d", a+10)}}
		for n := 0; n < 20; n++ {
			c := x.connection(s, at.Add(time.Duration(n)*time.Minute+time.Duration(a)*time.Second), "198.51.100.30", 8080, "ESTABLISHED", "http", 32, true)
			i.Network.Connections = append(i.Network.Connections, c)
			g.Connections = append(g.Connections, c)
			member.HitIDs = append(member.HitIDs, c.SourceID)
		}
		ds := scope(asset, "udp://192.0.2.53:53")
		di := x.input(ds, at, end)
		di.DNS = &evidence.DNSData{Provenance: prov("synthetic-group-registry")}
		for n := 0; n < 5; n++ {
			domain := "pool-fixture.test"
			ip := "198.51.100.30"
			rcode := 0
			if n > 0 {
				domain = fmt.Sprintf("update-%d.unavailable-fixture.test", n)
				ip = ""
				rcode = 3
			}
			r := x.dns(ds, at.Add(time.Duration(n)*time.Second), domain, ip, rcode)
			di.DNS.Records = append(di.DNS.Records, r)
			g.DNS = append(g.DNS, r)
			g.DNSOwnership[r.SourceID] = asset
		}
		g.Members = append(g.Members, member)
		x.addInput(i)
		x.addInput(di)
	}
	g.Baselines = []evidence.Baseline{{Provenance: prov("baseline-botnet-group"), FactID: "F_SHARED_ENDPOINT", Metrics: map[string]float64{"endpoint_frequency": 0.001, "endpoint_frequency_p01": 0.01}}, {Provenance: prov("baseline-botnet-group"), FactID: "F_GROUP_NXDOMAIN_CLUSTER", Metrics: map[string]float64{"group_nxdomain_rate_p99": 0.1}}}
	x.source("baseline-botnet-group", map[string]any{"cohort": "separate synthetic normal cohort, September 2026", "endpoint_frequency": 0.001, "endpoint_frequency_p01": 0.01, "group_nxdomain_rate_p99": 0.1})
	x.s.Bundle.Inputs.Request.Groups = []evidence.GroupInput{g}
	// Actual group-only scope is part of the existing F/S domain contract.
	sub := x.subject(evidence.Scope{GroupID: g.ID}, g.Window, "group:"+g.ID)
	for _, m := range g.Members {
		index := x.mat(sub, "group_member", fmt.Sprintf("%s independently contacted %s 20 times; workstation update automation remains possible", m.AssetID, g.Endpoint), m.HitIDs...)
		sub.Materials[index].AssetID = m.AssetID
		sub.Materials[index].Role = m.Role
	}
	x.s.Bundle.Inputs.SemanticMaterials.Subjects = append(x.s.Bundle.Inputs.SemanticMaterials.Subjects, *sub)
}

func (x *builder) phishing() {
	x.s.Directory = "mock-03-phishing-credential"
	x.s.Title = "Phishing钓鱼与凭据提交"
	x.s.Background = "员工浏览器访问仿冒Contoso测试登录页，经历两次有明确事务边的跳转，页面表单向另一测试域提交合成用户名及占位密码。另有真实授权测试域的正常登录作对照；不使用真实凭据或外部站点。"
	x.asset("employee-phish", "192.0.2.40", "workstation")
	at := x.s.Bundle.History.End
	end := at.Add(time.Hour)
	s := scope("employee-phish", "tcp://203.0.113.40:80")
	i := x.input(s, at, end)
	c := x.connection(s, at, "203.0.113.40", 80, "ESTABLISHED", "http", 128, true)
	i.Network = &evidence.NetworkData{Provenance: prov(c.SourceID), Connections: []evidence.Connection{c}, ServicesVerified: true, Services: []evidence.Service{{Port: 80, Protocol: "http"}}}
	page := `<html><title>Contoso secure account verification</title><h1>Contoso sign in - verify immediately</h1><form action="http://collector-fixture.test/submit" method="POST"><input name="username"><input name="password" type="password"><button>Verify account</button></form></html>`
	urls := []string{"http://cont0so.test/start", "http://cont0so.test/continue", "http://cont0so.test/login", "http://collector-fixture.test/submit", "http://accounts.contoso.test/login"}
	for n, u := range urls {
		body := ""
		method := "GET"
		response := "HTTP/1.1 200 OK\r\n\r\n" + page
		if n < 2 {
			response = "HTTP/1.1 302 Found\r\nLocation: " + urls[n+1] + "\r\n\r\nSynthetic redirect"
		}
		if n == 3 || n == 4 {
			method = "POST"
			body = "username=synthetic_user&password=PLACEHOLDER_NOT_A_SECRET"
			response = "HTTP/1.1 200 OK\r\n\r\nSynthetic form received; no credential misuse established"
		}
		r := x.http(s, at.Add(time.Second+time.Duration(n)*5*time.Second), u, method, body, response)
		r.DeclaredBrand = "Contoso"
		r.BrandClaimVerified = true
		if n == 2 {
			r.FormAction = "http://collector-fixture.test/submit"
		}
		if i.HTTP == nil {
			i.HTTP = &evidence.HTTPData{Provenance: prov(r.SourceID), BrandsVerified: true, Brands: []evidence.Brand{{Name: "Contoso", AuthorizedDomains: []string{"contoso.test", "accounts.contoso.test"}}}}
		}
		i.HTTP.Records = append(i.HTTP.Records, r)
		i.HTTP.RequestCandidates++
	}
	for n := 0; n < 2; n++ {
		r := &i.HTTP.Records[n]
		r.ResponseStatus = 302
		r.ResponseLocation = urls[n+1]
		r.RedirectToTransactionID = i.HTTP.Records[n+1].TransactionID
		r.RedirectVerified = true
	}
	// Make phase-one records reflect exactly the same parsed transactions.
	for n := range x.s.Bundle.Inputs.Manifest.PhaseOne.Records {
		r := &x.s.Bundle.Inputs.Manifest.PhaseOne.Records[n]
		for _, h := range i.HTTP.Records {
			if r.HTTP != nil && r.HTTP.SourceID == h.SourceID {
				copy := h
				r.HTTP = &copy
			}
		}
	}
	x.source("brand-registry-phishing", map[string]any{"brand": "Contoso", "authorized_domains": []string{"contoso.test", "accounts.contoso.test"}, "scope": "synthetic approved login service; collector-fixture.test unlisted; alternate outsourced login requires human verification"})
	for _, n := range []int{2, 3, 4} {
		r := i.HTTP.Records[n]
		observed := x.s.Sources[r.SourceID].(map[string]any)["data"].(map[string]any)["response"].(string)
		x.httpSubject(i, r, observed, func(sub *evidence.SemanticSubject) {
			if n == 2 {
				x.mat(sub, "page", page, r.SourceID)
			}
			host, _ := url.Parse(r.URL)
			x.mat(sub, "host", host.Hostname(), r.SourceID)
			x.mat(sub, "brand", "Contoso account login", "brand-registry-phishing")
			auth := "Approved: contoso.test and accounts.contoso.test"
			if n != 4 {
				auth += "; collector-fixture.test is not approved"
			}
			x.mat(sub, "brand_authorization", auth, "brand-registry-phishing")
			if r.Method == "POST" {
				idx := x.mat(sub, "credential_fields", r.ParsedBody+"; action="+r.URL, r.SourceID)
				sub.Materials[idx].FieldNames = []string{"username", "password"}
				sub.Materials[idx].TransactionID = r.TransactionID
				sub.Materials[idx].Method = r.Method
				sub.Materials[idx].Destination = r.URL
			}
		})
	}
	ds := scope(s.AssetID, "udp://192.0.2.53:53")
	di := x.input(ds, at.Add(-time.Minute), end)
	di.DNS = &evidence.DNSData{Provenance: prov("brand-registry-phishing")}
	for n, domain := range []string{"cont0so.test", "collector-fixture.test", "accounts.contoso.test"} {
		di.DNS.Records = append(di.DNS.Records, x.dns(ds, at.Add(-time.Duration(10-n)*time.Second), domain, "203.0.113.40", 0))
	}
	x.addInput(i)
	x.addInput(di)
}

func (x *builder) network() {
	x.s.Directory = "mock-04-network-exploit"
	x.s.Title = "Network Activity扫描与利用尝试"
	x.s.Background = "内网测试探测器对12个目的端口发起短时探测，合成生命周期记录区分终结失败、建立成功和SYN_SENT；一条HTTP请求含无害MOCK_EXPLOIT_TEST标记，另有授权健康检查反例。不存在可执行利用代码或成功执行证据。"
	x.asset("scanner-net", "192.0.2.60", "scanner")
	at := x.s.Bundle.History.End
	end := at.Add(time.Hour)
	as := scope("scanner-net", "asset://scanner-net")
	wide := x.input(as, at, end)
	wide.Network = &evidence.NetworkData{Provenance: prov("registry-scanner-net"), ServicesVerified: true}
	for n := 0; n < 12; n++ {
		port := uint16(8000 + n)
		s := scope(as.AssetID, fmt.Sprintf("tcp://203.0.113.60:%d", port))
		i := x.input(s, at, end)
		state := "REFUSED"
		terminal := true
		if n%4 == 0 {
			state = "ESTABLISHED"
		}
		if n == 11 {
			state = "SYN_SENT"
			terminal = false
		}
		payload := uint64(0)
		if state == "ESTABLISHED" {
			payload = 32
		}
		c := x.connection(s, at.Add(time.Duration(n)*3*time.Second), "203.0.113.60", port, state, "http", payload, terminal)
		i.Network = &evidence.NetworkData{Provenance: prov(c.SourceID), Connections: []evidence.Connection{c}, ServicesVerified: true, Services: []evidence.Service{{Port: port, Protocol: "http"}}}
		x.baseline(i, "F_CONN_FAIL_RATE", map[string]float64{"connection_failure_rate_p95": 0.1}, nil)
		wide.Network.Connections = append(wide.Network.Connections, c)
		wide.Network.Services = append(wide.Network.Services, evidence.Service{Port: port, Protocol: "http"})
		x.addInput(i)
	}
	for n := 0; n < 4; n++ {
		s := scope(as.AssetID, fmt.Sprintf("tcp://198.51.100.%d:443", 70+n))
		i := x.input(s, at, end)
		c := x.connection(s, at.Add(time.Duration(n)*time.Minute+10*time.Minute), fmt.Sprintf("198.51.100.%d", 70+n), 443, "ESTABLISHED", "tls", 256, true)
		i.Network = &evidence.NetworkData{Provenance: prov(c.SourceID), Connections: []evidence.Connection{c}, ServicesVerified: true, Services: []evidence.Service{{Port: 443, Protocol: "tls"}}}
		wide.Network.Connections = append(wide.Network.Connections, c)
		x.addInput(i)
	}
	wide.Network.Services = append(wide.Network.Services, evidence.Service{Port: 443, Protocol: "tls"})
	x.baseline(wide, "F_FANOUT_SINGLE_SRC", map[string]float64{"unique_targets_per_hour_p99": 8}, nil)
	x.baseline(wide, "F_CONN_FAIL_RATE", map[string]float64{"connection_failure_rate_p95": 0.1}, nil)
	x.s.Bundle.Inputs.Request.AssetInputs = []evidence.Input{*wide}
	s := scope(as.AssetID, "tcp://203.0.113.60:8080")
	i := x.input(s, at, end)
	connection := x.connection(s, at.Add(44*time.Second), "203.0.113.60", 8080, "ESTABLISHED", "http", 128, true)
	wide.Network.Connections = append(wide.Network.Connections, connection)
	wide.Network.Services = append(wide.Network.Services, evidence.Service{Port: 8080, Protocol: "http"})
	response := "HTTP/1.1 400 Bad Request\r\n\r\nMOCK_EXPLOIT_TEST rejected; no execution"
	r := x.http(s, at.Add(45*time.Second), "http://target-fixture.test:8080/test-endpoint", "POST", "marker=MOCK_EXPLOIT_TEST&action=simulate_only", response)
	r.ResponseStatus = 400
	i.HTTP = &evidence.HTTPData{Provenance: prov(r.SourceID), Records: []evidence.HTTPRecord{r}, RequestCandidates: 1}
	x.httpSubject(i, r, response, func(sub *evidence.SemanticSubject) { x.mat(sub, "parsed_payload", r.ParsedBody, r.SourceID) })
	normal := x.http(s, at.Add(50*time.Second), "http://target-fixture.test:8080/health", "GET", "", "HTTP/1.1 200 OK\r\n\r\nAuthorized health check")
	i.HTTP.Records = append(i.HTTP.Records, normal)
	i.HTTP.RequestCandidates++
	i.Network = &evidence.NetworkData{Provenance: prov(connection.SourceID, r.SourceID, normal.SourceID), Connections: []evidence.Connection{connection}, ServicesVerified: true, Services: []evidence.Service{{Port: 8080, Protocol: "http"}}, Sessions: []evidence.Session{
		{SourceID: r.SourceID, ID: r.SessionID, Start: r.Time, End: r.Time.Add(time.Second), UpBytes: uint64(len(r.RawRequest)), DownBytes: uint64(len(response)), VolumeVerified: true, HitIDs: []string{r.SourceID}},
		{SourceID: normal.SourceID, ID: normal.SessionID, Start: normal.Time, End: normal.Time.Add(time.Second), UpBytes: uint64(len(normal.RawRequest)), DownBytes: uint64(len("HTTP/1.1 200 OK\r\n\r\nAuthorized health check")), VolumeVerified: true, HitIDs: []string{normal.SourceID}},
	}}
	x.httpSubject(i, normal, "HTTP/1.1 200 OK\r\n\r\nAuthorized health check", func(sub *evidence.SemanticSubject) {
		x.mat(sub, "parsed_payload", normal.RawRequest, normal.SourceID)
	})
	x.addInput(i)
}

func (x *builder) finish() {
	b := &x.s.Bundle
	p := b.Inputs.Manifest.PhaseOne
	n := int64(len(b.Inputs.Request.Hits))
	b.Snapshot.Count = n
	b.Inputs.Manifest.DeclaredHits = n
	b.Inputs.Manifest.LoadedHits = n
	b.Inputs.Manifest.BoundHits = n
	p.RawHits = n
	ss := service.PhaseOneSnapshotSource{EventID: b.Event.EventID, Version: 1, Watermark: 1, RevisionWatermark: 1, LoadedHits: n, Complete: true}
	p.Sources = append([]service.PhaseOneSnapshotSource{ss}, p.Sources...)
	for k := range p.CurrentContacts {
		p.CurrentContacts[k].Snapshot = ss
	}
	for k := range p.Contacts {
		if p.Contacts[k].Snapshot.EventID == ss.EventID {
			p.Contacts[k].Snapshot = ss
		}
	}
	b.History.CandidateCount = len(b.History.Rows)
	sort.SliceStable(x.s.Timeline, func(i, j int) bool {
		return x.s.Timeline[i]["time"].(time.Time).Before(x.s.Timeline[j]["time"].(time.Time))
	})
	b.Snapshot.Context["occurrence_count"] = n
	b.Snapshot.Context["event_background"] = x.s.Background
	if len(b.Inputs.Request.Hits) > 0 {
		first, last := b.Inputs.Request.Hits[0].OccurredAt, b.Inputs.Request.Hits[0].OccurredAt
		for _, h := range b.Inputs.Request.Hits {
			if h.OccurredAt.Before(first) {
				first = h.OccurredAt
			}
			if h.OccurredAt.After(last) {
				last = h.OccurredAt
			}
		}
		b.Snapshot.Context["first_time"] = first
		b.Snapshot.Context["last_time"] = last
		b.Event.CreatedAt, b.Event.UpdatedAt, b.Event.LastSeenAt = first, last, ptr(last)
	}
	b.Event.Title, b.Event.Message, b.Event.Source = x.s.Title, x.s.Background, "synthetic-fixture-offline"
	b.Event.EventStatus, b.Event.ReviewStatus, b.Event.Severity = "new", "pending", "unknown"
	if len(b.History.Rows) == 0 {
		b.History.Status, b.History.ExactRelations = "unavailable", false
		b.History.Reason = "synthetic_history_not_supplied"
	}
	// Update provenance source lists to the actual family records, not one
	// arbitrarily chosen representative; preserve separate registry baselines.
	for _, set := range [][]evidence.Input{b.Inputs.Request.Inputs, b.Inputs.Request.AssetInputs} {
		for k := range set {
			in := &set[k]
			if in.HTTP != nil {
				in.HTTP.SourceIDs = nil
				for _, r := range in.HTTP.Records {
					in.HTTP.SourceIDs = append(in.HTTP.SourceIDs, r.SourceID)
				}
			}
			if in.DNS != nil {
				in.DNS.SourceIDs = nil
				for _, r := range in.DNS.Records {
					in.DNS.SourceIDs = append(in.DNS.SourceIDs, r.SourceID)
				}
			}
			if in.Network != nil {
				in.Network.SourceIDs = nil
				for _, r := range in.Network.Connections {
					in.Network.SourceIDs = append(in.Network.SourceIDs, r.SourceID)
				}
				for _, r := range in.Network.Sessions {
					in.Network.SourceIDs = append(in.Network.SourceIDs, r.SourceID)
				}
			}
			if in.HTTP != nil {
				for _, h := range in.HTTP.Records {
					entry := x.s.Sources[h.SourceID].(map[string]any)["data"].(map[string]any)
					entry["http"] = h
					for n := range p.Records {
						if p.Records[n].Hit.ID == h.SourceID {
							copy := h
							p.Records[n].HTTP = &copy
						}
					}
				}
			}
		}
	}
	b.Coverage = service.PreparedInputCoverage(b.Inputs)
	x.source(b.Event.EventID, b.Event)
	x.source(fmt.Sprintf("%s:%d", b.Event.EventID, b.Snapshot.Version), b.Snapshot)
	b.Seal()
}
