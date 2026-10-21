package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderDNSHexLabelMaterials(t *testing.T) {
	for _, tc := range []struct {
		name, question, decoded string
		wire                    bool
	}{
		{"non_first_label", "prefix.636174202f6574632f706173737764.agent.test", "cat /etc/passwd", true},
		{"four_byte_label", "prefix.63617420.agent.test", "cat ", true},
		{"uppercase_hex", "prefix.43415420.agent.test", "CAT ", true},
		{"non_first_base32", "prefix.MNQXIIBPMV2GGL3QMFZXG53E.agent.test", "cat /etc/passwd", true},
		{"lowercase_base32", "prefix.mnqxiibpmv2ggl3qmfzxg53e.agent.test", "cat /etc/passwd", true},
		{"short_base32", "prefix.NBSWY3DP.agent.test", "hello", true},
		{"mixed_ambiguous", "63617420.NBSWY3DP.agent.test", "", true},
		{"ordinary_domain", "ordinary.agent.test", "", true},
		{"ambiguous_labels", "636174202f6574632f706173737764.636174202f6574632f67726f7570.agent.test", "", true},
		{"binary_label", "prefix.000102030405.agent.test", "", true},
		{"metadata_only", "prefix.636174202f6574632f706173737764.agent.test", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, input := providerDNSHexFixture(t, tc.question, tc.wire)
			before := digest(input)
			r := buildSnapshotSemanticRequest(snap, input, &evidence.Result{}, evidence.SemanticRaw)
			r.Slots = []evidence.SlotKey{{ID: "S04", Target: "c2.dns_encoded_intent"}}
			engine, err := evidence.NewSemanticEngine(evidence.DefaultSemanticConfig())
			if err != nil {
				t.Fatal(err)
			}
			plan, err := engine.Plan(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			result, err := engine.Evaluate(context.Background(), r, reportSemanticModelFunc(func(_ context.Context, call evidence.SemanticCall) (string, error) {
				calls++
				return acceptedSemanticResponse(t, call), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if tc.decoded == "" {
				if len(plan.Tasks) != 0 || calls != 0 || len(result.Findings) != 0 {
					t.Fatal("ineligible or ambiguous question produced a semantic task", plan.Tasks)
				}
			} else {
				if len(plan.Tasks) != 1 {
					t.Fatal("verified encoded question lost its decode chain", plan.Executions)
				}
				facts := plan.Tasks[0].Facts
				if len(facts) != 1 || facts[0].ID != "F_DNS_ENCODED_LABEL" || facts[0].Status != evidence.Observed || len(facts[0].SourceIDs) != 1 || facts[0].SourceIDs[0] != "dns-hit" {
					t.Fatal("semantic task lacks exact same-question hard fact", facts)
				}
				if calls != 1 || len(result.Findings) != 1 || result.Findings[0].Slot.String() != "S04/c2.dns_encoded_intent/" || result.Findings[0].StructureValidation != "passed" || result.Findings[0].BehaviorOutcome != "not_established" {
					t.Fatal("fact/decode/controlled-Stub execution did not complete", result)
				}
				var domain, encoded, decoded, proof *evidence.SemanticMaterial
				for i := range r.Subjects {
					for j := range r.Subjects[i].Materials {
						m := &r.Subjects[i].Materials[j]
						switch m.Kind {
						case "domain":
							domain = m
						case "encoded_payload":
							encoded = m
						case "decoded_payload":
							decoded = m
						case "decode":
							proof = m
						}
					}
				}
				if domain == nil || encoded == nil || decoded == nil || proof == nil || decoded.Text != tc.decoded || !strings.Contains(encoded.FieldPath, "labels[1]") {
					t.Fatal("decode content or original label locator missing", domain, encoded, decoded, proof)
				}
				if len(proof.DecodeSteps) != 1 || proof.DecodeSteps[0].InputID != encoded.ID || proof.DecodeSteps[0].OutputID != decoded.ID || len(domain.RelatedIDs) != 2 {
					t.Fatal("decode chain not linked to this exact question", domain, proof)
				}
				for _, m := range []*evidence.SemanticMaterial{domain, encoded, decoded, proof} {
					if len(m.Provenance.SourceIDs) != 1 || m.Provenance.SourceIDs[0] != "dns-hit" || m.Scope != domain.Scope || m.SnapshotVersion != 1 {
						t.Fatal("decode escaped source binding", m)
					}
				}
			}
			if digest(input) != before {
				t.Fatal("semantic material construction mutated frozen input")
			}
			if input.Manifest.DNSMessageParseCount != 1 && tc.wire {
				t.Fatal("DNS was reparsed rather than reusing decoded question", input.Manifest.DNSMessageParseCount)
			}
		})
	}
}

func providerDNSHexFixture(t *testing.T, question string, wire bool) (EvidenceSnapshot, SnapshotEvidenceInput) {
	t.Helper()
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	name, err := dnsmessage.NewName(question + ".")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m := phaseOneWire(t, at, 10, payload, true, false)
	m["app"] = map[string]any{"dns_query": question}
	if !wire {
		delete(m, "raw_packet")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	snap := EvidenceSnapshot{EventID: "dns-event", Version: 1, Sources: []string{"dns-event"}, Count: 1}
	input, _, _, err := assembleProviderTraffic(snap, []domain.Asset{{ID: "asset-a", Address: "192.0.2.1", Status: 1}}, []store.Hit{{ID: "dns-hit", EventID: snap.EventID, OccurredAt: at, Raw: raw}}, evidence.AnalysisWindow{Start: at, End: at.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return snap, input
}

func TestProviderDNSFirstHexMaterialIdentity(t *testing.T) {
	// The model transcript contains quotes and hashes of these materials.
	// An equivalent supported question must keep the entire material payload,
	// rather than rewriting the saved model response to match new wording.
	p := evidence.Provenance{Verified: true, Complete: true, Version: "frozen:1", SourceIDs: []string{"dns-hit"}}
	factory := func(s *evidence.SemanticSubject, kind, text, path string, p evidence.Provenance, complete bool) evidence.SemanticMaterial {
		return evidence.SemanticMaterial{ID: s.ID + ":" + kind, Kind: kind, Text: text, FieldPath: path, Provenance: p, Truncated: !complete}
	}
	d := evidence.SemanticMaterial{ID: "operation:dns-hit:domain", Kind: "domain", Text: "636174202f6574632f706173737764.agent.test", Provenance: p}
	previous := evidence.SemanticSubject{ID: "operation:dns-hit", Materials: []evidence.SemanticMaterial{d}}
	current := evidence.SemanticSubject{ID: "operation:dns-hit", Materials: []evidence.SemanticMaterial{d}}
	addSemanticDecodeMaterials(&previous, strings.Split(d.Text, ".")[0], []string{d.ID}, factory, p)
	addProviderDNSHexMaterials(&current, d, factory, p)
	if digest(previous.Materials) != digest(current.Materials) {
		t.Fatal("equivalent first-label hex changed saved material identity", previous.Materials, current.Materials)
	}
}
