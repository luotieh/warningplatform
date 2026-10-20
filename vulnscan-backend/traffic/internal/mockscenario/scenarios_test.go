package mockscenario

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/service"
)

func fixtureRoot() string {
	return filepath.Join("..", "..", "..", "..", "docs", "evidence-pipeline-v2", "mock-scenarios")
}

// Load the independent checked-in JSON, not generated expected verdicts.
func TestFourCompositeScenariosEndToEnd(t *testing.T) {
	for _, name := range []string{"mock-01-c2-beacon", "mock-02-botnet-coordination", "mock-03-phishing-credential", "mock-04-network-exploit"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, file := range []string{"prepared-bundle.json", "sources.json"} {
				raw, err := os.ReadFile(filepath.Join(fixtureRoot(), name, file))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, file), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			o, err := Run(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			b, err := readBundle(filepath.Join(dir, "prepared-bundle.json"))
			if err != nil {
				t.Fatal(err)
			}
			if o.Contract.LedgerPath != "Evidence.normalized_evidence" || o.Contract.SnapshotIdentity.LoadedHits != int64(len(b.Inputs.Request.Hits)) || !o.Contract.SnapshotIdentity.Complete {
				t.Fatalf("incorrect normalized identity: %+v", o.Contract)
			}
			metrics := o.Evidence.Pipeline.Metrics
			if metrics.SnapshotReadPages != 0 || metrics.HistoryMetadataPages != 0 || metrics.HistoricalSnapshotLookups != 0 || metrics.HistoricalReadPages != 0 || metrics.WireFrameDecodes != 0 || metrics.HTTPRequestParses != 0 || metrics.DNSMessageParses != 0 {
				t.Fatalf("prepared execution fetched or reparsed: %+v", metrics)
			}
			if o.Semantics.Result.Calls == 0 {
				t.Fatal("no real Stub call")
			}
			for _, f := range o.Semantics.Result.Findings {
				if f.ExplanationOnly && f.Strength != "none" {
					t.Fatal("explanation upgraded to risk support")
				}
			}
			if name == "mock-02-botnet-coordination" {
				found := false
				for _, f := range o.Evaluation.Result.Findings {
					if f.FactID == "F_TIME_COORDINATION" && f.Status == evidence.Observed {
						found = true
					}
					if f.FactID == "F_INFECTION_CHAIN" && f.Status == evidence.Observed {
						t.Fatal("invented infection chain")
					}
				}
				if !found {
					t.Fatal("group observations were not evaluated")
				}
			}
			if name == "mock-01-c2-beacon" {
				command := false
				for _, f := range o.Semantics.Result.Findings {
					if f.Slot.ID == "S13" && f.Slot.Subtype == "command" {
						command = true
					}
				}
				if !command {
					t.Fatal("request-bound decoded command was not evaluated")
				}
			}
			if name == "mock-04-network-exploit" {
				pending, failures, successes := 0.0, 0.0, 0.0
				for _, f := range o.Evaluation.Result.Findings {
					if f.FactID != "F_CONN_FAIL_RATE" {
						continue
					}
					pending += f.Measurements.Values["pending"]
					failures += f.Measurements.Values["confirmed_failures"]
					successes += f.Measurements.Values["confirmed_successes"]
				}
				// These are independently counted lifecycle records in the input:
				// 12 probe ports = 8 REFUSED + 3 ESTABLISHED + 1 SYN_SENT.
				if pending != 1 || failures != 8 || successes != 3 {
					t.Fatalf("lifecycle accounting: pending=%v failures=%v successes=%v", pending, failures, successes)
				}
				negative := false
				for _, f := range o.Semantics.Result.Findings {
					if f.Slot.ID == "S09" && f.Judgement == "contradict" {
						negative = true
					}
				}
				if !negative {
					t.Fatal("health-check counterexample lost")
				}
			}
		})
	}
}

func TestGroupContractRejectsCrossAssetSource(t *testing.T) {
	b, err := readBundle(filepath.Join(fixtureRoot(), "mock-02-botnet-coordination", "prepared-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	b.Inputs.Request.Groups[0].Members[0].HitIDs[0] = b.Inputs.Request.Groups[0].Members[1].HitIDs[0]
	b.Seal()
	if err = b.Validate(); err == nil || !strings.Contains(err.Error(), "prepared_group_member_source_mismatch") {
		t.Fatalf("forged member accepted: %v", err)
	}
}

func TestGroupContractRejectsUndeclaredSemanticScope(t *testing.T) {
	b, err := readBundle(filepath.Join(fixtureRoot(), "mock-02-botnet-coordination", "prepared-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	b.Inputs.SemanticMaterials.Subjects[0].Scope.GroupID = "invented-group"
	b.Seal()
	if err = b.Validate(); err == nil || !strings.Contains(err.Error(), "prepared_invalid_semantic_scope") {
		t.Fatalf("undeclared group accepted: %v", err)
	}
}

func TestSemanticValidationRejectsForeignReference(t *testing.T) {
	b, err := readBundle(filepath.Join(fixtureRoot(), "mock-01-c2-beacon", "prepared-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := service.ExecutePreparedEvidence(context.Background(), b, service.PreparedExecutionOptions{SemanticMode: service.PreparedSemanticStub, SemanticModel: &ControlledModel{}})
	if err != nil {
		t.Fatal(err)
	}
	s := *o.Semantics.Result
	s.Findings[0].MaterialRefs = append(s.Findings[0].MaterialRefs, "nonexistent-material")
	if err = evidence.ValidateSemanticResult(s.Plan, s); err == nil {
		t.Fatal("foreign semantic reference accepted")
	}
}

func TestFixtureRawAndParsedAssociations(t *testing.T) {
	for _, name := range []string{"mock-01-c2-beacon", "mock-02-botnet-coordination", "mock-03-phishing-credential", "mock-04-network-exploit"} {
		b, err := readBundle(filepath.Join(fixtureRoot(), name, "prepared-bundle.json"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(fixtureRoot(), name, "sources.json"))
		if err != nil {
			t.Fatal(err)
		}
		var sources map[string]struct {
			Data struct {
				RawRequest string `json:"raw_request"`
				Response   string `json:"response"`
			} `json:"data"`
		}
		if err = json.Unmarshal(raw, &sources); err != nil {
			t.Fatal(err)
		}
		hits := map[string]evidence.Hit{}
		for _, h := range b.Inputs.Request.Hits {
			hits[h.ID] = h
		}
		for _, in := range b.Inputs.Request.Inputs {
			if in.Network != nil {
				for _, c := range in.Network.Connections {
					h := hits[c.SourceID]
					u, _ := url.Parse(h.Scope.EndpointID)
					if u.Hostname() != c.Destination || !h.OccurredAt.Equal(c.Time) || h.Scope.AssetID != c.AssetID {
						t.Fatal("connection/hit mismatch", name, c.SourceID)
					}
				}
			}
			if in.HTTP != nil {
				for _, h := range in.HTTP.Records {
					src := sources[h.SourceID].Data
					if src.RawRequest != b.Inputs.HTTP[h.SourceID].Raw || !strings.HasPrefix(src.Response, "HTTP/1.1 "+fmt.Sprint(h.ResponseStatus)) {
						t.Fatal("raw/parsed HTTP mismatch", name, h.SourceID)
					}
					if in.Network != nil {
						for _, session := range in.Network.Sessions {
							if session.SourceID == h.SourceID && (session.ID != h.SessionID || session.UpBytes != uint64(len(src.RawRequest)) || session.DownBytes != uint64(len(src.Response))) {
								t.Fatal("session volume mismatch", name, h.SourceID)
							}
						}
					}
				}
			}
		}
		for _, subject := range b.Inputs.SemanticMaterials.Subjects {
			for _, m := range subject.Materials {
				if m.Kind != "protocol_request" && m.Kind != "protocol_response" {
					continue
				}
				for _, id := range m.Provenance.SourceIDs {
					src := sources[id].Data
					text := src.RawRequest
					if m.Kind == "protocol_response" {
						text = src.Response
					}
					if m.Text != text {
						t.Fatal("semantic material differs from raw transaction", name, m.ID)
					}
				}
			}
		}
	}
}
