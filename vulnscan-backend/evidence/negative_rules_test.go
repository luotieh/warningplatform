package evidence

import (
	"fmt"
	"testing"
	"time"
)

func negativeFixture(id FactID) (Request, Config) {
	r, c := fullFixture(id)
	start := r.Hits[0].OccurredAt
	if groupRule(id) {
		x := &r.Groups[0]
		removed := x.Members[2].AssetID
		x.Members = x.Members[:2]
		connections := []Connection{}
		for _, record := range x.Connections {
			if record.AssetID != removed {
				connections = append(connections, record)
			}
		}
		x.Connections = connections
		dns := []DNSRecord{}
		for _, record := range x.DNS {
			if x.DNSOwnership[record.SourceID] != removed {
				dns = append(dns, record)
			}
		}
		x.DNS = dns
		return r, c
	}
	i := &r.Inputs[0]
	b := func(name string, value float64) { i.Baselines[0].Metrics[name] = value }
	switch id {
	case BeaconPeriodic:
		r.Hits[7].OccurredAt = start.Add(2 * time.Hour)
	case MultiDayPersist:
		r.Hits[7].OccurredAt = start.Add(7 * time.Minute)
	case "F_BEACON_JITTER":
		for j := range r.Hits {
			r.Hits[j].OccurredAt = start.Add(time.Duration(j) * time.Minute)
		}
	case "F_FIXED_DAILY_WINDOW":
		for j := range r.Hits {
			r.Hits[j].OccurredAt = start.AddDate(0, 0, j%3).Add(time.Duration(j) * 3 * time.Hour)
		}
	case "F_RATE_BURST":
		b("burst_ratio_p99", 1000)
	case "F_RATE_RAMP":
		r.Hits = nil
		packets := uint64(1)
		scope := i.Scope
		for bucket := 0; bucket < 5; bucket++ {
			for j := 0; j < 4-bucket; j++ {
				r.Hits = append(r.Hits, Hit{ID: fmt.Sprintf("descending%d-%d", bucket, j), OccurredAt: start.Add(time.Duration(bucket)*5*time.Minute + time.Duration(j)*time.Second), Packets: &packets, Scope: scope})
			}
		}
	case "F_DNS_HIGH_ENTROPY":
		b("unique_subdomain_ratio_p95", 1)
	case "F_DNS_ENCODED_LABEL":
		i.DNS.Records[0].Domain = "normal.example.com"
	case "F_DGA_LEXICAL":
		b("bigram_log_probability_p05", -100)
	case "F_NXDOMAIN_CLUSTER":
		b("nxdomain_rate_p99", 1)
	case "F_FAILED_TO_ACTIVE":
		i.Network.Connections[0].Destination = "203.0.113.99"
	case "F_HTTP_ENDPOINT_REPEAT":
		for j := range i.HTTP.Records {
			i.HTTP.Records[j].Time = start.Add(time.Duration(1<<j) * time.Second)
		}
	case "F_HTTP_FIELD_ENCODING":
		i.HTTP.Records[0].Fields = map[string]string{"message": "hello"}
	case "F_HTTP_UA_RARITY":
		b("ua_frequency", 0.1)
	case "F_HTTP_SIZE_STABILITY":
		b("size_cv_p05", 0)
	case "F_LONG_LOW_SESSION":
		i.Network.Sessions[0].Start = start
		i.Network.Sessions[0].End = start.Add(10 * time.Minute)
	case "F_URL_ODD_AUTHORITY", "F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR":
		i.HTTP.Records[0].URL = "https://example.com/api"
	case "F_CRED_POST_STRUCTURE":
		i.HTTP.Records[0].Method = "GET"
	case "F_FORM_CROSSSITE":
		i.HTTP.Records[0].FormAction = "/submit"
	case "F_REDIRECT_CHAIN":
		i.HTTP.Records[2].Method = "GET"
	case "F_MULTI_REDIRECT_CHAIN":
		i.HTTP.Records[0].RedirectToTransactionID = ""
	case "F_PROTOCOL_PORT_MISMATCH":
		i.Network.Services[0].Protocol = "http"
	case "F_RARE_PORT":
		i.Baselines[0].Frequencies["22"] = 0.1
	case "F_INFRA_RARITY":
		i.Baselines[0].Frequencies["synthetic-AS|ZZ|unknown"] = 0.1
	case "F_FANOUT_SINGLE_SRC":
		for j := range i.Network.Connections {
			i.Network.Connections[j].Destination = "203.0.113.1"
		}
	case "F_PORT_SEQUENCE":
		ports := []uint16{1, 8, 2, 7, 3, 6, 4, 5}
		for j := range i.Network.Connections {
			i.Network.Connections[j].Port = ports[j]
		}
		c.Policies[id] = map[string]float64{"difference_entropy_threshold": 10}
	case "F_SMALL_PACKET":
		v := uint64(512)
		i.Network.Connections[0].PayloadBytes = &v
	case "F_CONN_FAIL_RATE":
		i.Network.Connections[0].TCPState = "ESTABLISHED"
	case "F_INDEPENDENT_RULE_CORROB":
		i.Corroboration.Rules[1].OriginalSource = i.Corroboration.Rules[0].OriginalSource
	case "F_INDEPENDENT_INTEL_CORROB":
		i.Corroboration.Intelligence[1].OriginalSource = i.Corroboration.Intelligence[0].OriginalSource
	case "F_IOC_TYPE_CORROB":
		i.Corroboration.IOCType = "BT"
	case "F_TLS_SNI_MISMATCH":
		i.TLS.Records[0].CertificateNames = []string{"other.com"}
	case "F_TLS_CERT_ANOMALY":
		i.TLS.Records[0].NotBefore = start.Add(-time.Hour)
	case "F_TLS_JA_MISMATCH":
		i.TLS.FingerprintClients["fingerprint"] = "browser"
	case "F_IOC_NOVELTY", "F_DST_NOVELTY":
		i.History.Events = []HistoryEvent{{ID: "previous", Time: start.AddDate(0, 0, -1), AssetID: i.Scope.AssetID, IOC: i.History.IOC, Endpoint: i.History.Endpoint}}
	case "F_HIST_ASSET_IOC_RECURRENCE":
		i.History.Events[1].Time = i.History.Events[0].Time.Add(time.Minute)
	case "F_HIST_GROUP_RECURRENCE":
		i.History.Events[0].Time = start.AddDate(0, 0, -14)
		i.History.Events[1].Time = start.AddDate(0, 0, -13)
	case "F_HIST_INFRA_PERSISTENCE":
		i.History.Events[1].AssetID = i.History.Events[0].AssetID
	case "F_HIST_SCHEDULE_MATCH":
		for j := range i.History.Events {
			i.History.Events[j].Time = i.History.Events[j].Time.Add(3 * time.Hour)
		}
	case "F_HIST_MULTI_IOC_SIEGE":
		for j := range i.History.Events {
			i.History.Events[j].IOC = "one-ioc"
		}
	case "F_HIST_STAGE_PROGRESSION":
		i.History.Events[0].Stage = "c2"
		i.History.Events[1].Stage = "scan"
	case "F_HIST_COORD_PARAM_MATCH":
		i.History.Events[0].Parameters["phase"] = 100
	case "F_HIST_EXERCISE", "F_EXCL_SCAN_TASK", "F_EXCL_INFRA_ROLE":
		i.Authorizations.Records[0].AssetID = "unrelated-asset"
	}
	return r, c
}
func TestAll59RulesHaveNegativeComputations(t *testing.T) {
	for _, id := range SupportedFacts() {
		t.Run(string(id), func(t *testing.T) {
			r, c := negativeFixture(id)
			e, err := NewEngine(c)
			if err != nil {
				t.Fatal(err)
			}
			out := evaluate(t, e, r)
			if len(out.Findings) != 1 || out.Findings[0].Status != NotObserved || out.Findings[0].Eligibility != "eligible" {
				t.Fatalf("negative fixture did not refute condition: %+v", out.Findings)
			}
		})
	}
}

func TestGroupCoordinationNegativeWithThreeVerifiedMembers(t *testing.T) {
	r, c := groupFixture("F_TIME_COORDINATION")
	for j := range r.Groups[0].Connections {
		if r.Groups[0].Connections[j].AssetID == "asset2" {
			r.Groups[0].Connections[j].Time = r.Groups[0].Connections[j].Time.Add(2 * time.Minute)
		}
	}
	e, _ := NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != NotObserved {
		t.Fatal("desynchronized member accepted")
	}
}
