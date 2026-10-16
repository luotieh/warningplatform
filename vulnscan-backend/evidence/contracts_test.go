package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func contractFinding(t *testing.T, r Request, c Config) Finding {
	t.Helper()
	e, err := NewEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	out := evaluate(t, e, r)
	if len(out.Findings) != 1 {
		t.Fatalf("unexpected scope count: %d", len(out.Findings))
	}
	return out.Findings[0]
}

func TestFailedToActiveRequiresSameQuestionAndActualConnection(t *testing.T) {
	for _, mode := range []string{"same_normalized_question", "other_question", "other_subdomain", "wrong_answer_ip", "late_connection", "other_asset", "invented_source", "wrong_source_time", "duplicate_failure"} {
		t.Run(mode, func(t *testing.T) {
			r, c := fullFixture("F_FAILED_TO_ACTIVE")
			d, n := r.Inputs[0].DNS, r.Inputs[0].Network
			want := NotObserved
			switch mode {
			case "same_normalized_question":
				want = Observed
			case "other_question":
				d.Records[0].Domain = "a.example"
				d.Records[1].Domain = "a.example"
			case "other_subdomain":
				d.Records[0].Domain = "a.active.com"
				d.Records[1].Domain = "a.active.com"
			case "wrong_answer_ip":
				d.Records[2].Answers = []string{"203.0.113.8"}
			case "late_connection":
				d.Records[2].Time = n.Connections[0].Time.Add(-6 * time.Minute)
			case "other_asset":
				n.Connections[0].AssetID = "unrelated"
				want = Missing
			case "invented_source":
				n.Connections[0].SourceID = "invented"
				want = Missing
			case "wrong_source_time":
				n.Connections[0].Time = n.Connections[0].Time.Add(time.Second)
				want = Missing
			case "duplicate_failure":
				d.Records[1].SourceID = d.Records[0].SourceID
				want = Missing
			}
			if f := contractFinding(t, r, c); f.Status != want {
				t.Fatalf("want %s, got %+v", want, f)
			}
		})
	}
}

func TestEveryGroupRuleRejectsUnboundConnection(t *testing.T) {
	for _, id := range SupportedFacts() {
		if !groupRule(id) {
			continue
		}
		for _, mode := range []string{"nonexistent_hit", "wrong_asset_hit", "wrong_time", "wrong_ip", "wrong_port", "wrong_protocol", "duplicate_connection"} {
			t.Run(string(id)+"/"+mode, func(t *testing.T) {
				r, c := groupFixture(id)
				x := &r.Groups[0]
				row := &x.Connections[0]
				switch mode {
				case "nonexistent_hit":
					row.SourceID = "fabricated"
				case "wrong_asset_hit":
					row.SourceID = x.Connections[8].SourceID
				case "wrong_time":
					row.Time = row.Time.Add(time.Second)
				case "wrong_ip":
					row.Destination = "203.0.113.200"
				case "wrong_port":
					row.Port = 8443
				case "wrong_protocol":
					row.Transport = "udp"
				case "duplicate_connection":
					x.Connections = append(x.Connections, *row)
				}
				f := contractFinding(t, r, c)
				if f.Status != Missing || f.ReasonCode != UnresolvedBinding {
					t.Fatalf("unbound group accepted: %+v", f)
				}
			})
		}
	}
}

func TestGroupEndpointIdentityCannotMergePortsOrProtocols(t *testing.T) {
	for _, id := range []FactID{"F_SHARED_ENDPOINT", "F_TIME_COORDINATION"} {
		for _, mode := range []string{"empty_endpoint", "ip_only", "different_ports", "different_transport", "dns_is_not_connection"} {
			t.Run(string(id)+"/"+mode, func(t *testing.T) {
				r, c := groupFixture(id)
				x := &r.Groups[0]
				want := NotObserved
				switch mode {
				case "empty_endpoint":
					x.Endpoint = ""
					want = Missing
				case "ip_only":
					x.Endpoint = "203.0.113.10"
					want = Missing
				case "different_ports":
					for j := range x.Connections {
						if x.Connections[j].AssetID == "asset2" {
							x.Connections[j].Port = 8443
						}
					}
					bindGroupFixture(&r)
				case "different_transport":
					for j := range x.Connections {
						if x.Connections[j].AssetID == "asset2" {
							x.Connections[j].Transport = "udp"
						}
					}
					bindGroupFixture(&r)
				case "dns_is_not_connection":
					x.Connections = []Connection{}
					for _, m := range x.Members {
						x.DNS = append(x.DNS, DNSRecord{SourceID: m.AssetID, Domain: x.Endpoint, Time: x.Window.Start})
						x.DNSOwnership[m.AssetID] = m.AssetID
					}
				}
				if f := contractFinding(t, r, c); f.Status != want {
					t.Fatalf("want %s got %+v", want, f)
				}
			})
		}
	}
}

func TestConnectionFailureOutcomes(t *testing.T) {
	for _, tc := range []struct {
		state    string
		verified bool
		want     Status
	}{
		{"SYN_SENT", true, Missing}, {"SYN_SENT", false, Missing}, {"RST", false, Missing}, {"RST", true, Observed},
		{"TIMEOUT", true, Observed}, {"ESTABLISHED", true, NotObserved}, {"ESTABLISHED", false, Missing}, {"CLOSED", true, Missing}, {"UNKNOWN", true, Missing},
	} {
		t.Run(tc.state+"/"+string(tc.want), func(t *testing.T) {
			r, c := fullFixture("F_CONN_FAIL_RATE")
			row := &r.Inputs[0].Network.Connections[0]
			row.TCPState = tc.state
			row.OutcomeVerified = tc.verified
			f := contractFinding(t, r, c)
			if f.Status != tc.want {
				t.Fatalf("%+v", f)
			}
			if tc.state == "SYN_SENT" && (f.Measurements.Values["confirmed_failures"] != 0 || f.Measurements.Values["pending"] != 1) {
				t.Fatal("pending counted as failure")
			}
		})
	}
	r, c := fullFixture("F_CONN_FAIL_RATE")
	n := r.Inputs[0].Network
	success := n.Connections[0]
	success.SourceID = "success"
	success.TCPState = "ESTABLISHED"
	n.Connections = append(n.Connections, success)
	f := contractFinding(t, r, c)
	if f.Measurements.Values["connection_failure_rate"] != .5 {
		t.Fatalf("wrong denominator: %+v", f)
	}
	pending := success
	pending.TCPState = "SYN_SENT"
	pending.SourceID = "pending"
	n.Connections = append(n.Connections, pending)
	if f := contractFinding(t, r, c); f.Status != Missing || f.Measurements.Values["terminal_outcomes"] != 2 {
		t.Fatalf("incomplete cohort: %+v", f)
	}
}

func TestWeakerFeatureClaimsStayTruthful(t *testing.T) {
	r, c := fullFixture("F_SMALL_PACKET")
	f := contractFinding(t, r, c)
	if f.Status != Observed || f.Measurements.Values["zero_payload_fraction"] != 0 {
		t.Fatal("nonzero small payload claimed zero")
	}
	for _, tc := range []struct {
		id        FactID
		forbidden string
	}{
		{"F_HTTP_SIZE_STABILITY", "响应"}, {"F_MULTI_REDIRECT_CHAIN", "短链"}, {"F_TLS_SNI_MISMATCH", "目的"}, {"F_SMALL_PACKET", "无载荷"}, {"F_INFECTION_CHAIN", "感染"}, {"F_HIST_INFRA_PERSISTENCE", "钓鱼"},
	} {
		for _, d := range Definitions() {
			if d.ID == tc.id && strings.Contains(d.Description, tc.forbidden) {
				t.Fatalf("overclaim: %+v", d)
			}
		}
	}
	// One temporal A/B path is a valid feature, never an infection verdict.
	r, c = fullFixture("F_INFECTION_CHAIN")
	f = contractFinding(t, r, c)
	if f.Status != Observed || !strings.Contains(f.CannotProve, "不证明感染") {
		t.Fatalf("%+v", f)
	}
	// Stable request bodies say nothing about responses or shortener ownership.
	for _, id := range []FactID{"F_HTTP_SIZE_STABILITY", "F_MULTI_REDIRECT_CHAIN", "F_TLS_SNI_MISMATCH", "F_HIST_INFRA_PERSISTENCE"} {
		r, c = fullFixture(id)
		f = contractFinding(t, r, c)
		if f.Status != Observed || f.CannotProve == "" {
			t.Fatalf("%+v", f)
		}
	}
}

// A positive feature fixture with its mandatory source/trust removed must not
// become a negative or survive as observed. These complement the 59 distinct
// numeric/content negatives in negative_rules_test.go; they are not production
// or malicious-intent accuracy tests.
func TestAll59RejectUnverifiedFeatureSources(t *testing.T) {
	for _, id := range SupportedFacts() {
		t.Run(string(id), func(t *testing.T) {
			r, c := fullFixture(id)
			if groupRule(id) {
				r.Groups[0].Verified = false
			} else {
				switch id {
				case MultiDayPersist:
					// Partial coverage permits a sourced positive; invalid times do not.
					for j := range r.Hits {
						r.Hits[j].OccurredAt = time.Time{}
					}
				case BeaconPeriodic, "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_RATE_BURST", "F_RATE_RAMP":
					r.Quality.Coverage = CoverageUnknown
				case "F_LONG_LOW_SESSION":
					r.Inputs[0].Network.Verified = false
				default:
					for _, family := range FactInputs(id) {
						switch family {
						case "dns_records":
							r.Inputs[0].DNS.Verified = false
						case "http_records":
							r.Inputs[0].HTTP.Verified = false
						case "network_records":
							r.Inputs[0].Network.Verified = false
						case "history":
							r.Inputs[0].History.Verified = false
						case "tls_records":
							r.Inputs[0].TLS.Verified = false
						case "authorization_records":
							r.Inputs[0].Authorizations.Verified = false
						case "independent_rule_and_intel_metadata":
							r.Inputs[0].Corroboration.Verified = false
						}
					}
				}
			}
			if f := contractFinding(t, r, c); f.Status != Missing {
				t.Fatalf("unverified source survived: %+v", f)
			}
		})
	}
}

// These are controlled model responses. Acceptance proves only citation and
// strength contracts, not that model semantics match a human ground truth.
func TestAll23SemanticSupportContradictionAndFalseCitation(t *testing.T) {
	for _, spec := range semanticSpecs {
		for _, mode := range []string{"support", "contradict", "invented_quote"} {
			t.Run(spec.Key.String()+"/"+mode, func(t *testing.T) {
				r := semanticFixture(spec)
				e := semanticTestEngine(t)
				out, err := e.Evaluate(context.Background(), r, semanticModelFunc(func(_ context.Context, call SemanticCall) (string, error) {
					return semanticResponse(call, func(item *SemanticItem) {
						if mode == "contradict" {
							item.Judgement = "contradict"
						}
						if mode == "invented_quote" {
							for j := range item.Quotes {
								item.Quotes[j].Excerpt = "THIS TEXT IS NOT IN THE MATERIAL"
							}
						}
					}), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "invented_quote" {
					if len(out.Findings) != 0 {
						t.Fatal("fabricated evidence accepted")
					}
					return
				}
				if len(out.Findings) != 1 {
					t.Fatalf("%+v", out)
				}
				f := out.Findings[0]
				if f.StructureValidation != "passed" || f.SemanticSupport != mode || f.BehaviorOutcome != "not_established" {
					t.Fatalf("%+v", f)
				}
				plan, err := e.Plan(context.Background(), r)
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateSemanticResult(plan, out); err != nil {
					t.Fatal(err)
				}
				out.Findings[0].BehaviorOutcome = "execution_succeeded"
				if err := ValidateSemanticResult(plan, out); err == nil {
					t.Fatal("cached model interpretation promoted to outcome")
				}
			})
		}
	}
}

func Test82ContractsReachNormalizedEvidence(t *testing.T) {
	n := Normalize(nil, nil)
	if len(n.Items) != 82 {
		t.Fatalf("registry size %d", len(n.Items))
	}
	for _, u := range n.Items {
		raw, _ := json.Marshal(u)
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		for _, key := range []string{"feature_claim", "security_interpretation", "cannot_prove", "required_correlations"} {
			if fields[key] == nil || fields[key] == "" {
				t.Fatalf("%s missing %s", u.RuleID, key)
			}
		}
		if u.Status != "unavailable" {
			t.Fatal("registration promoted to acceptance")
		}
	}
	if len(PhaseOneFacts()) != 5 || len(PhaseOneSlots()) != 4 || len(PhaseOneDefinitions()) != 7 {
		t.Fatal("phase one scope expanded")
	}
}

func TestSemanticContractsDoNotExposeMutableRegistrySlices(t *testing.T) {
	defs := SemanticDefinitions()
	original := defs[0].RequiredCorrelations[0]
	defs[0].RequiredCorrelations[0] = "tampered catalog"
	e := semanticTestEngine(t)
	r := semanticFixture(semanticSpecs[0])
	plan, err := e.Plan(context.Background(), r)
	if err != nil || len(plan.Tasks) == 0 {
		t.Fatalf("%v", err)
	}
	plan.Tasks[0].Slot.RequiredCorrelations[0] = "tampered plan"
	if SemanticDefinitions()[0].RequiredCorrelations[0] != original {
		t.Fatal("caller mutated global semantic contract")
	}
	next, err := e.Plan(context.Background(), r)
	if err != nil || next.Tasks[0].Slot.RequiredCorrelations[0] != original {
		t.Fatal("caller changed future semantic tasks")
	}
}
