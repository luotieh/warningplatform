package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"
)

func fixtureProvenance() Provenance {
	return Provenance{Verified: true, Complete: true, Version: "synthetic-fixture-v1", SourceIDs: []string{"synthetic-source"}}
}
func fixtureBaseline(id FactID, metrics map[string]float64) Baseline {
	return Baseline{Provenance: fixtureProvenance(), FactID: id, Metrics: metrics}
}
func fullFixture(id FactID) (Request, Config) {
	r := testRequest()
	r.Facts = []FactID{id}
	c := DefaultConfig()
	c.Policies = map[FactID]map[string]float64{}
	start := r.Hits[0].OccurredAt
	scope := r.Hits[0].Scope
	i := Input{Scope: scope, Window: &AnalysisWindow{Start: start, End: start.Add(time.Hour)}}
	http := &HTTPData{Provenance: fixtureProvenance()}
	size := uint64(32)
	for j := 0; j < 8; j++ {
		http.Records = append(http.Records, HTTPRecord{SourceID: fmt.Sprintf("http%d", j), TransactionID: fmt.Sprintf("tx%d", j), SessionID: "session1", Time: start.Add(time.Duration(j) * time.Minute), URL: "https://example.com/api", Method: "GET", UserAgent: "synthetic-agent", BodyLength: &size})
	}
	conn := Connection{SourceID: "connection1", AssetID: scope.AssetID, Time: start, Destination: "203.0.113.10", Port: 22, AppProtocol: "http", ProtocolParsed: true, TCPState: "RST"}
	network := &NetworkData{Provenance: fixtureProvenance(), Connections: []Connection{conn}}
	dns := &DNSData{Provenance: fixtureProvenance(), Records: []DNSRecord{{SourceID: "dns1", Time: start, Domain: "example.com", RCode: 3, RCodeKnown: true}}}
	history := &HistoryData{Provenance: fixtureProvenance(), AsOf: start, LookbackStart: start.AddDate(0, 0, -30), IOC: "synthetic-ioc", Endpoint: scope.EndpointID}
	i.HTTP = http
	i.Network = network
	i.DNS = dns
	i.History = history
	baseHistory := HistoryEvent{ID: "previous1", Time: start.AddDate(0, 0, -2), AssetID: scope.AssetID, IOC: history.IOC, Endpoint: history.Endpoint, Adjudication: "malicious", AdjudicationID: "adjudication1", AdjudicationSource: "human"}
	setBaseline := func(metrics map[string]float64) { i.Baselines = []Baseline{fixtureBaseline(id, metrics)} }
	switch id {
	case BeaconPeriodic:
	case MultiDayPersist:
		r.Hits[7].OccurredAt = start.AddDate(0, 0, 1)
	case "F_BEACON_JITTER":
		r.Hits = nil
		t := start
		packets := uint64(1)
		for j := 0; j < 17; j++ {
			r.Hits = append(r.Hits, Hit{ID: fmt.Sprintf("jitter%d", j), OccurredAt: t, Packets: &packets, Scope: scope})
			delta := 50
			if j >= 8 {
				delta = 70
			}
			t = t.Add(time.Duration(delta) * time.Second)
		}
		c.Policies[id] = map[string]float64{"ljung_box_lags": 2, "median_relative_tolerance": 0.5}
	case "F_FIXED_DAILY_WINDOW":
		for j := range r.Hits {
			r.Hits[j].OccurredAt = start.AddDate(0, 0, j%3).Add(time.Duration(j) * time.Second)
		}
	case "F_RATE_BURST":
		i.Window.End = start.Add(25 * time.Minute)
		setBaseline(map[string]float64{"mean_per_5m": 1, "burst_ratio_p99": 2})
	case "F_RATE_RAMP":
		i.Window.End = start.Add(25 * time.Minute)
		r.Hits = nil
		packets := uint64(1)
		for bucket := 0; bucket < 5; bucket++ {
			for j := 0; j <= bucket; j++ {
				r.Hits = append(r.Hits, Hit{ID: fmt.Sprintf("ramp%d-%d", bucket, j), OccurredAt: start.Add(time.Duration(bucket)*5*time.Minute + time.Duration(j)*time.Second), Packets: &packets, Scope: scope})
			}
		}
		c.Policies[id] = map[string]float64{"window_seconds": 300}
	case "F_DNS_HIGH_ENTROPY":
		dns.Records = nil
		for j := 0; j < 3; j++ {
			dns.Records = append(dns.Records, DNSRecord{SourceID: fmt.Sprintf("dns%d", j), Time: start, Domain: fmt.Sprintf("verylongsubdomainnumber%d.example.com", j), RCodeKnown: true})
		}
		setBaseline(map[string]float64{"unique_subdomain_ratio_p95": 0.1, "label_length_p95": 4, "query_rate_p95": 0})
	case "F_DNS_ENCODED_LABEL":
		dns.Records[0].Domain = "41424344.example.com"
	case "F_DGA_LEXICAL":
		dns.Records[0].Domain = "xzqr.com"
		dns.BigramLogProbabilities = map[string]float64{"xz": -8, "zq": -8, "qr": -8}
		setBaseline(map[string]float64{"bigram_log_probability_p05": -2, "vowel_ratio_p05": 0.1, "vowel_ratio_p95": 0.9, "length_p05": 3, "length_p95": 20})
	case "F_NXDOMAIN_CLUSTER":
		dns.Records = append(dns.Records, DNSRecord{SourceID: "dns2", Time: start, Domain: "other.com", RCode: 3, RCodeKnown: true})
		setBaseline(map[string]float64{"nxdomain_rate_p99": 0.5})
	case "F_FAILED_TO_ACTIVE":
		dns.Records[0].Time = start.Add(-3 * time.Minute)
		dns.Records = append(dns.Records, DNSRecord{SourceID: "dns2", Time: start.Add(-2 * time.Minute), Domain: "other.com", RCode: 3, RCodeKnown: true}, DNSRecord{SourceID: "dns3", Time: start.Add(-time.Minute), Domain: "active.com", RCode: 0, RCodeKnown: true, Answers: []string{conn.Destination}})
		c.Policies[id] = map[string]float64{"min_failures": 2}
	case "F_HTTP_ENDPOINT_REPEAT":
	case "F_HTTP_FIELD_ENCODING":
		http.Records[0].Fields = map[string]string{"blob": "4142434445464748"}
		setBaseline(map[string]float64{"encoded_field_ratio_p95": 0.5, "encoded_field_length_p95": 8})
	case "F_HTTP_UA_RARITY":
		setBaseline(map[string]float64{"ua_frequency": 0.001, "ua_frequency_p01": 0.01})
	case "F_HTTP_SIZE_STABILITY":
		for j := 8; j < 12; j++ {
			record := http.Records[0]
			record.SourceID = fmt.Sprintf("http%d", j)
			record.Time = start.Add(time.Duration(j) * time.Minute)
			http.Records = append(http.Records, record)
		}
		setBaseline(map[string]float64{"size_cv_p05": 0.1, "unique_size_ratio_p05": 0.2})
	case "F_LONG_LOW_SESSION":
		network.Sessions = []Session{{SourceID: "session-source", ID: "session1", Start: start.Add(-31 * time.Minute), End: start.Add(10 * time.Minute), UpBytes: 50, DownBytes: 50, VolumeVerified: true}}
		for _, h := range r.Hits {
			network.Sessions[0].HitIDs = append(network.Sessions[0].HitIDs, h.ID)
		}
	case "F_URL_ODD_AUTHORITY":
		http.Records[0].URL = "https://user@203.0.113.10/login"
	case "F_URL_HOMOGLYPH", "F_BRAND_IMPOSTOR":
		http.Records[0].URL = "https://examp1e.com/login"
		http.BrandsVerified = true
		http.Brands = []Brand{{Name: "example", AuthorizedDomains: []string{"example.com"}}}
		if id == "F_BRAND_IMPOSTOR" {
			c.Policies[id] = map[string]float64{"max_edit_distance": 1}
		}
	case "F_URL_BRAND_SUBDOMAIN_TRICK":
		http.Records[0].URL = "https://example.com.evil.com/login"
		http.BrandsVerified = true
		http.Brands = []Brand{{Name: "example", AuthorizedDomains: []string{"example.com"}}}
	case "F_CRED_POST_STRUCTURE":
		http.Records[0].Method = "POST"
		http.Records[0].Fields = map[string]string{"password": "synthetic-redacted"}
	case "F_FORM_CROSSSITE":
		http.Records[0].FormAction = "https://other.com/collect"
	case "F_REDIRECT_CHAIN", "F_MULTI_REDIRECT_CHAIN":
		http.Records = []HTTPRecord{
			{SourceID: "http1", TransactionID: "tx1", SessionID: "session1", Time: start, URL: "https://link.example.com/", ResponseStatus: 302, ResponseLocation: "https://relay.other.com/", ResponseVerified: true, RedirectVerified: true, RedirectToTransactionID: "tx2"},
			{SourceID: "http2", TransactionID: "tx2", SessionID: "session1", Time: start.Add(time.Second), URL: "https://relay.other.com/", ResponseStatus: 302, ResponseLocation: "https://landing.bad.com/", ResponseVerified: true, RedirectVerified: true, RedirectToTransactionID: "tx3"},
			{SourceID: "http3", TransactionID: "tx3", SessionID: "session1", Time: start.Add(2 * time.Second), URL: "https://landing.bad.com/", Method: "POST", Fields: map[string]string{"password": "synthetic-redacted"}},
		}
	case "F_PROTOCOL_PORT_MISMATCH":
		network.ServicesVerified = true
		network.Services = []Service{{Port: 22, Protocol: "ssh"}}
	case "F_RARE_PORT":
		setBaseline(map[string]float64{"port_frequency_p01": 0.01})
		i.Baselines[0].Frequencies = map[string]float64{"22": 0.001}
	case "F_INFRA_RARITY":
		network.ASN = "synthetic-AS"
		network.Country = "ZZ"
		network.Reputation = "unknown"
		setBaseline(map[string]float64{"infra_frequency_p01": 0.01})
		i.Baselines[0].Frequencies = map[string]float64{"synthetic-AS|ZZ|unknown": 0.001}
	case "F_FANOUT_SINGLE_SRC":
		network.Connections = nil
		for j := 0; j < 8; j++ {
			record := conn
			record.SourceID = fmt.Sprintf("conn%d", j)
			record.Destination = fmt.Sprintf("203.0.113.%d", j+1)
			network.Connections = append(network.Connections, record)
		}
		setBaseline(map[string]float64{"unique_targets_per_hour_p99": 4})
	case "F_PORT_SEQUENCE":
		network.Connections = nil
		for j := 0; j < 8; j++ {
			record := conn
			record.SourceID = fmt.Sprintf("conn%d", j)
			record.Port = uint16(j + 20)
			record.Time = start.Add(time.Duration(j) * time.Second)
			network.Connections = append(network.Connections, record)
		}
	case "F_SMALL_PACKET":
		payload := uint64(1)
		network.Connections[0].PayloadBytes = &payload
		c.Policies[id] = map[string]float64{"small_payload_bytes": 64}
	case "F_CONN_FAIL_RATE":
		setBaseline(map[string]float64{"connection_failure_rate_p95": 0.1})
	case "F_INDEPENDENT_RULE_CORROB", "F_INDEPENDENT_INTEL_CORROB", "F_IOC_TYPE_CORROB":
		i.Corroboration = &CorroborationData{Provenance: fixtureProvenance(), IOC: "ioc", IOCType: "C2", HardScoresVerified: true, HardTypeScores: map[string]float64{"C2": 40, "BT": 5, "PH": 0}, Rules: []RuleRecord{{ID: "rule1", IndependenceGroup: "group1", OriginalSource: "original1"}, {ID: "rule2", IndependenceGroup: "group2", OriginalSource: "original2"}}, Intelligence: []IntelRecord{{ID: "intel1", IOC: "ioc", OriginalSource: "original1"}, {ID: "intel2", IOC: "ioc", OriginalSource: "original2"}}}
	case "F_TLS_SNI_MISMATCH", "F_TLS_CERT_ANOMALY", "F_TLS_JA_MISMATCH":
		i.TLS = &TLSData{Provenance: fixtureProvenance(), ExceptionsVerified: true, IssuersVerified: true, TrustedIssuers: []string{"issuer"}, FingerprintsVerified: true, FingerprintClients: map[string]string{"fingerprint": "scanner"}, Records: []TLSRecord{{SourceID: "tls1", Time: start, SNI: "other.com", CertificateNames: []string{"example.com"}, ChainVerified: true, ChainValid: true, NotBefore: start.Add(time.Minute), NotAfter: start.AddDate(0, 1, 0), Issuer: "issuer", UserAgent: "Mozilla/5.0", Fingerprint: "fingerprint"}}}
	case "F_DST_NOVELTY", "F_IOC_NOVELTY":
	case "F_HIST_ASSET_IOC_RECURRENCE":
		history.Events = []HistoryEvent{baseHistory}
		second := baseHistory
		second.ID = "previous2"
		second.AdjudicationID = "adjudication2"
		second.Time = start.AddDate(0, 0, -1)
		history.Events = append(history.Events, second)
	case "F_HIST_GROUP_RECURRENCE":
		history.GroupID = "history-group"
		history.GroupMembershipVerified = true
		history.CurrentMemberIDs = []string{"a", "b", "c"}
		baseHistory.GroupID = history.GroupID
		baseHistory.MemberIDs = history.CurrentMemberIDs
		baseHistory.Time = start.AddDate(0, 0, -15)
		history.Events = []HistoryEvent{baseHistory}
		second := baseHistory
		second.ID = "previous2"
		second.AdjudicationID = "adjudication2"
		second.Time = start.AddDate(0, 0, -8)
		history.Events = append(history.Events, second)
	case "F_HIST_INFRA_PERSISTENCE":
		history.Events = []HistoryEvent{baseHistory}
		second := baseHistory
		second.ID = "previous2"
		second.AdjudicationID = "adjudication2"
		second.AssetID = "another-asset"
		second.Time = start.AddDate(0, 0, -1)
		history.Events = append(history.Events, second)
	case "F_HIST_SCHEDULE_MATCH":
		history.Events = []HistoryEvent{baseHistory}
		second := baseHistory
		second.ID = "previous2"
		second.AdjudicationID = "adjudication2"
		second.Time = start.AddDate(0, 0, -1)
		history.Events = append(history.Events, second)
		c.Policies[id] = map[string]float64{"kl_threshold": 0.1}
	case "F_HIST_MULTI_IOC_SIEGE":
		for j := 0; j < 3; j++ {
			row := baseHistory
			row.ID = fmt.Sprintf("previous%d", j)
			row.IOC = fmt.Sprintf("ioc%d", j)
			history.Events = append(history.Events, row)
		}
		setBaseline(map[string]float64{"distinct_ioc_families_p99": 2})
	case "F_HIST_STAGE_PROGRESSION":
		history.CurrentStage = "exfil"
		history.CurrentStageSource = "hard_facts"
		history.CurrentStageProvenance = fixtureProvenance()
		baseHistory.Stage = "scan"
		history.Events = []HistoryEvent{baseHistory}
		second := baseHistory
		second.ID = "previous2"
		second.AdjudicationID = "adjudication2"
		second.Time = start.AddDate(0, 0, -1)
		second.Stage = "c2"
		history.Events = append(history.Events, second)
	case "F_HIST_COORD_PARAM_MATCH":
		history.CampaignID = "verified-campaign"
		history.CampaignProvenance = fixtureProvenance()
		baseHistory.CampaignID = history.CampaignID
		baseHistory.CampaignProvenance = fixtureProvenance()
		history.CurrentParametersVerified = true
		history.CurrentParameters = map[string]float64{"phase": 60}
		baseHistory.Parameters = map[string]float64{"phase": 60}
		history.Events = []HistoryEvent{baseHistory}
		c.Policies[id] = map[string]float64{"parameter_relative_tolerance": 0.1}
	case "F_HIST_EXERCISE", "F_EXCL_SCAN_TASK", "F_EXCL_INFRA_ROLE":
		a := AuthorizationRecord{ID: "authorization1", Start: start.Add(-time.Hour), End: start.Add(time.Hour), AssetID: scope.AssetID, Endpoint: scope.EndpointID, Ports: []uint16{22}, Protocols: []string{"http"}, Targets: []string{"203.0.113.0/24"}}
		switch id {
		case "F_HIST_EXERCISE":
			a.TaskType = "phishing_exercise"
		case "F_EXCL_SCAN_TASK":
			a.Role = "scanner"
			a.TaskType = "scan"
		case "F_EXCL_INFRA_ROLE":
			a.Role = "proxy"
		}
		i.Authorizations = &AuthorizationData{Provenance: fixtureProvenance(), Records: []AuthorizationRecord{a}}
	default:
		if groupRule(id) {
			return groupFixture(id)
		}
	}
	r.Inputs = []Input{i}
	return r, c
}

func groupFixture(id FactID) (Request, Config) {
	r := testRequest()
	r.Facts = []FactID{id}
	r.Hits = nil
	c := DefaultConfig()
	c.Policies = map[FactID]map[string]float64{}
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	x := GroupInput{Provenance: fixtureProvenance(), ID: "synthetic-group", Window: AnalysisWindow{Start: start, End: start.Add(10 * time.Minute)}, IOC: "203.0.113.10", Endpoint: "203.0.113.10", DNSOwnership: map[string]string{}}
	packets := uint64(1)
	for asset := 0; asset < 3; asset++ {
		name := fmt.Sprintf("asset%d", asset)
		scope := Scope{AssetID: name, EndpointID: "endpoint", DeviceID: "device"}
		m := GroupMember{AssetID: name, Scope: scope, MembershipVerified: true, Subnet: fmt.Sprintf("192.0.%d.0/24", asset), Role: "workstation", Addresses: []string{fmt.Sprintf("192.0.2.%d", asset+1)}}
		for j := 0; j < 8; j++ {
			hid := fmt.Sprintf("hit%d-%d", asset, j)
			t := start.Add(time.Duration(j) * time.Minute)
			r.Hits = append(r.Hits, Hit{ID: hid, OccurredAt: t, Packets: &packets, Scope: scope})
			m.HitIDs = append(m.HitIDs, hid)
			x.Connections = append(x.Connections, Connection{SourceID: fmt.Sprintf("connection%d-%d", asset, j), AssetID: name, Time: t, Destination: x.Endpoint, Port: 443})
		}
		x.Members = append(x.Members, m)
	}
	switch id {
	case "F_GROUP_NXDOMAIN_CLUSTER", "F_SHARED_DOMAIN_CLUSTER":
		for j, m := range x.Members {
			source := fmt.Sprintf("dns%d", j)
			x.DNS = append(x.DNS, DNSRecord{SourceID: source, Time: start, Domain: "unusual.example.com", RCode: 3, RCodeKnown: true})
			x.DNSOwnership[source] = m.AssetID
		}
		b := fixtureBaseline(id, map[string]float64{"group_nxdomain_rate_p99": 0.5, "domain_frequency_p01": 0.01})
		b.Frequencies = map[string]float64{"example.com": 0.001}
		x.Baselines = []Baseline{b}
	case "F_MULTI_ASSET_IOC":
		c.Policies[id] = map[string]float64{"cluster_window_seconds": 500}
	case "F_SHARED_ENDPOINT":
		x.Baselines = []Baseline{fixtureBaseline(id, map[string]float64{"endpoint_frequency": 0.001, "endpoint_frequency_p01": 0.01})}
	case "F_MULTI_ASSET_DIST":
		c.Policies[id] = map[string]float64{"subnet_entropy_min": 1}
	case "F_TIME_COORDINATION":
		c.Policies[id] = map[string]float64{"bucket_seconds": 60}
	case "F_COORD_FANOUT":
	case "F_INFECTION_CHAIN":
		c.Policies[id] = map[string]float64{"chain_window_seconds": 300}
		x.Connections = append(x.Connections, Connection{SourceID: "spread", AssetID: x.Members[0].AssetID, Destination: x.Members[1].Addresses[0], Time: start.Add(30 * time.Second)})
	case "F_FIRST_VISIT_CLUSTER":
		x.History = &HistoryData{Provenance: fixtureProvenance(), AsOf: start, LookbackStart: start.AddDate(0, 0, -30)}
	case "F_COORD_PATTERN_RECURRENCE":
		c.Policies[id] = map[string]float64{"bucket_seconds": 60}
		x.Window.End = start.AddDate(0, 0, 2)
		original := append([]Connection(nil), x.Connections...)
		for _, record := range original {
			record.Time = record.Time.AddDate(0, 0, 1)
			record.SourceID += "-day2"
			x.Connections = append(x.Connections, record)
		}
	}
	r.Groups = []GroupInput{x}
	return r, c
}

func TestAll59RulesHavePositiveComputations(t *testing.T) {
	if len(SupportedFacts()) != 59 {
		t.Fatal("canonical catalog count changed")
	}
	for _, id := range SupportedFacts() {
		t.Run(string(id), func(t *testing.T) {
			r, c := fullFixture(id)
			e, err := NewEngine(c)
			if err != nil {
				t.Fatal(err)
			}
			out := evaluate(t, e, r)
			if len(out.Findings) != 1 {
				t.Fatalf("expected one canonical finding, got %d", len(out.Findings))
			}
			f := out.Findings[0]
			if f.FactID != id || f.Status != Observed || f.Eligibility != "eligible" {
				t.Fatalf("positive fixture not observed: %+v", f)
			}
			if len(f.SourceIDs) == 0 || f.SnapshotVersion != 1 {
				t.Fatalf("missing trace: %+v", f)
			}
			if _, err := json.Marshal(out); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAllAdditionalRulesHandleMissingInputs(t *testing.T) {
	for _, id := range SupportedFacts() {
		if id == BeaconPeriodic || id == MultiDayPersist {
			continue
		}
		t.Run(string(id), func(t *testing.T) {
			r := testRequest()
			r.Facts = []FactID{id}
			r.Quality = Quality{}
			out := evaluate(t, testEngine(t), r)
			if len(out.Findings) != 1 || out.Findings[0].Status != Missing {
				t.Fatalf("missing data gave verdict: %+v", out)
			}
		})
	}
}

func TestExactKendallKnownProbabilities(t *testing.T) {
	_, p, ok := exactKendall([]float64{1, 2, 3, 4, 5})
	if !ok || math.Abs(p-2.0/120) > 1e-12 {
		t.Fatalf("incorrect exact p: %v", p)
	}
	if _, _, ok := exactKendall([]float64{1, 2, 2, 4, 5}); ok {
		t.Fatal("ties silently accepted")
	}
	if _, _, ok := exactKendall([]float64{1, 2, 3, 4}); ok {
		t.Fatal("four observations accepted")
	}
	q, p, _, ok := ljungBox([]float64{1, 2, 3, 4, 5}, 1)
	if !ok || math.Abs(q-1.4) > 1e-12 || math.Abs(p-0.2367235706) > 1e-8 {
		t.Fatalf("incorrect Ljung-Box statistic: %v %v", q, p)
	}
}

func TestInvalidLinksAndUnreviewedStageRejected(t *testing.T) {
	r, c := fullFixture("F_REDIRECT_CHAIN")
	r.Inputs[0].HTTP.Records[1].SessionID = "unrelated"
	e, _ := NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("different sessions joined")
	}
	r, c = fullFixture("F_HIST_STAGE_PROGRESSION")
	r.Inputs[0].History.Events[0].AdjudicationSource = "llm"
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("AI history used as adjudication")
	}
	r, c = groupFixture("F_MULTI_ASSET_IOC")
	r.Groups[0].Members[0].MembershipVerified = false
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unverified group used")
	}
}

func TestAllRulesCanBeSelectedTogether(t *testing.T) {
	r := testRequest()
	r.Facts = SupportedFacts()
	out, err := testEngine(t).Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 59 {
		t.Fatalf("expected 59 results, got %d", len(out.Findings))
	}
}
