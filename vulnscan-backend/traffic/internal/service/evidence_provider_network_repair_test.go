package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func TestProviderNetworkRepairsReachPreparedBundle(t *testing.T) {
	s := store.NewMemoryStore()
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	providerTestEvent(t, s, "current", "a", "192.0.2.10", "d1", at)
	providerTestEvent(t, s, "peer", "b", "192.0.2.11", "d2", at)
	b, _, err := PrepareEvidenceFromPlatform(context.Background(), s, "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Inputs.Request.Groups) != 1 {
		t.Fatal("candidate group missing")
	}
	g := b.Inputs.Request.Groups[0]
	for _, member := range g.Members {
		want := map[string]string{"a": "192.0.2.10", "b": "192.0.2.11"}[member.AssetID]
		if want == "" || len(member.Addresses) != 1 || member.Addresses[0] != want {
			t.Fatal("collected exact address lost in prepared group", member)
		}
	}
	if g.Complete || len(g.Connections) != 2 || len(b.Inputs.Request.AssetInputs) != 2 {
		t.Fatal("repair changed coverage or lost existing observations", g)
	}
	for _, subject := range b.Inputs.SemanticMaterials.Subjects {
		if subject.Scope.GroupID == g.ID {
			t.Fatal("incomplete candidate became trusted semantic group", subject)
		}
	}
}

func TestProviderTrustedGroupBehaviorReachesSemanticMaterials(t *testing.T) {
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	proof := evidence.Provenance{Verified: true, Complete: true, Version: "group-registry", SourceIDs: []string{"registry-proof"}}
	g := evidence.GroupInput{ID: "trusted", Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}, Provenance: proof}
	input := SnapshotEvidenceInput{}
	for i := 0; i < 2; i++ {
		asset, id := fmt.Sprint("a", i), fmt.Sprint("h", i)
		scope := evidence.Scope{AssetID: asset, DeviceID: "device", EndpointID: "tcp://198.51.100.20:443"}
		input.Request.Hits = append(input.Request.Hits, evidence.Hit{ID: id, Scope: scope, OccurredAt: at})
		g.Members = append(g.Members, evidence.GroupMember{AssetID: asset, Scope: scope, HitIDs: []string{id}, Role: "workstation", MembershipVerified: true})
		g.Connections = append(g.Connections, evidence.Connection{SourceID: id, Time: at, AssetID: asset, Transport: "tcp", Destination: "198.51.100.20", Port: 443})
	}
	input.Request.Groups = []evidence.GroupInput{g}
	sem := buildSnapshotSemanticRequest(EvidenceSnapshot{EventID: "current", Version: 1}, input, &evidence.Result{}, evidence.SemanticRedacted)
	if len(sem.Subjects) != 1 || len(sem.Subjects[0].Materials) != 2 {
		t.Fatal("trusted group materials missing", sem)
	}
	for _, material := range sem.Subjects[0].Materials {
		if material.Kind != "group_member" || !strings.Contains(material.Text, "通信观测1条") || !strings.Contains(material.Text, "tcp://198.51.100.20:443") || !strings.Contains(material.Text, "不代表独立连接次数") {
			t.Fatal("actual bound behavior lost at semantic entry", material)
		}
	}
}

func TestProviderFirstVisitRequiresCompleteHistoricalAbsence(t *testing.T) {
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		complete bool
		prior    bool
		want     evidence.Status
	}{
		{name: "complete-no-prior", complete: true, want: evidence.Observed},
		{name: "complete-with-prior", complete: true, prior: true, want: evidence.NotObserved},
		{name: "partial-no-prior-is-not-first-visit", complete: false, want: evidence.Missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := evidence.Provenance{Verified: true, Complete: true, Version: "independent-first-visit", SourceIDs: []string{"group-proof"}}
			g := evidence.GroupInput{ID: "g", Endpoint: "tcp://198.51.100.20:443", Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}, Provenance: proof}
			historyProof := proof
			historyProof.Complete = tc.complete
			g.History = &evidence.HistoryData{Provenance: historyProof, PlatformRecords: true, AsOf: at, LookbackStart: at.Add(-24 * time.Hour)}
			r := evidence.Request{EventID: "current", SnapshotVersion: 1, Facts: []evidence.FactID{"F_FIRST_VISIT_CLUSTER"}}
			for i := 0; i < 3; i++ {
				asset, id := fmt.Sprint("asset", i), fmt.Sprint("hit", i)
				scope := evidence.Scope{AssetID: asset, DeviceID: "device", EndpointID: g.Endpoint}
				when := at.Add(time.Duration(i) * time.Minute)
				r.Hits = append(r.Hits, evidence.Hit{ID: id, Scope: scope, OccurredAt: when})
				g.Members = append(g.Members, evidence.GroupMember{AssetID: asset, Scope: scope, HitIDs: []string{id}, MembershipVerified: true})
				g.Connections = append(g.Connections, evidence.Connection{SourceID: id, AssetID: asset, Time: when, Transport: "tcp", Destination: "198.51.100.20", Port: 443})
			}
			if tc.prior {
				g.History.Events = []evidence.HistoryEvent{{ID: "prior", AssetID: "asset0", Time: at.Add(-time.Hour), Endpoint: g.Endpoint}}
			}
			r.Groups = []evidence.GroupInput{g}
			engine, err := evidence.NewEngine(evidence.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			result, err := engine.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != 1 || result.Findings[0].Status != tc.want {
				t.Fatalf("historical absence contract failed: %+v", result.Findings)
			}
		})
	}
}

func TestProviderMemberAddressesPreserveProofBoundaries(t *testing.T) {
	scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://198.51.100.20:443"}
	for _, tc := range []struct {
		name    string
		assets  []domain.Asset
		foreign bool
		want    string
	}{
		{name: "exact", assets: []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}}, want: "192.0.2.1"},
		{name: "ipv4-mapped", assets: []domain.Asset{{ID: "a", Address: "::ffff:192.0.2.1", Status: 1}}, want: "192.0.2.1"},
		{name: "disabled", assets: []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 0}}},
		{name: "ambiguous", assets: []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}, {ID: "b", Address: "192.0.2.1", Status: 1}}},
		{name: "prefix-is-not-host", assets: []domain.Asset{{ID: "a", Address: "192.0.2.0/24", Status: 1}}},
		{name: "hostname-is-not-address", assets: []domain.Asset{{ID: "a", Address: "server.example", Status: 1}}},
		{name: "foreign-hit", assets: []domain.Asset{{ID: "a", Address: "192.0.2.1", Status: 1}}, foreign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hitScope := scope
			if tc.foreign {
				hitScope.AssetID = "foreign"
			}
			req := evidence.Request{Hits: []evidence.Hit{{ID: "h", Scope: hitScope}}, Groups: []evidence.GroupInput{{ID: "candidate:g", Provenance: evidence.Provenance{Verified: true, Complete: false}, Members: []evidence.GroupMember{{AssetID: "a", Scope: scope, HitIDs: []string{"h"}, MembershipVerified: true}}}}}
			populateProviderMemberAddresses(&req, tc.assets)
			g, m := req.Groups[0], req.Groups[0].Members[0]
			if strings.Join(m.Addresses, ",") != tc.want || g.Complete || m.Role != "" || m.Subnet != "" {
				t.Fatal("address recovery changed identity/coverage contract", g)
			}
		})
	}
}

func TestProviderGroupSummaryOnlyUsesBoundedMemberSources(t *testing.T) {
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "tcp://198.51.100.20:443"}
	m := evidence.GroupMember{AssetID: "a", Scope: scope, Role: "workstation", MembershipVerified: true}
	g := evidence.GroupInput{ID: "g", Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Hour)}, Provenance: evidence.Provenance{Verified: true, Complete: true, Version: "test"}, DNSOwnership: map[string]string{}}
	hits := map[string]evidence.Hit{}
	for i := 0; i < 5; i++ {
		id := fmt.Sprint("h", i)
		m.HitIDs = append(m.HitIDs, id)
		g.SourceIDs = append(g.SourceIDs, id)
		hits[id] = evidence.Hit{ID: id, Scope: scope, OccurredAt: at.Add(time.Duration(i) * time.Minute)}
		g.Connections = append(g.Connections, evidence.Connection{SourceID: id, Time: hits[id].OccurredAt, AssetID: "a", Transport: "tcp", Destination: "198.51.100.20", Port: 443})
		g.DNS = append(g.DNS, evidence.DNSRecord{SourceID: id, Time: hits[id].OccurredAt, Domain: fmt.Sprintf("name%d.example", i)})
		g.DNSOwnership[id] = "a"
	}
	// Duplicates, foreign owners and wrong timestamps must not inflate counts
	// or expose unrelated source content in a member material.
	g.Connections = append(g.Connections, g.Connections[0], evidence.Connection{SourceID: "foreign", AssetID: "a", Destination: "203.0.113.9", Port: 443, Transport: "tcp", Time: at})
	g.DNS = append(g.DNS, evidence.DNSRecord{SourceID: "foreign", Domain: "foreign.example", Time: at}, evidence.DNSRecord{SourceID: "h0", Domain: "wrong-time.example", Time: at.Add(time.Second)})
	text := providerGroupMemberSummary(g, m, hits)
	for _, expected := range []string{"通信观测5条", "DNS观测5条", "tcp://198.51.100.20:443", "name0.example,name1.example,name2.example", "不代表独立连接次数", "不证明行为成功"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %s", expected, text)
		}
	}
	for _, forbidden := range []string{"foreign.example", "wrong-time.example", "203.0.113.9", "name3.example", "name4.example"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unbound or unbounded content %q", forbidden)
		}
	}
	// A group's provenance can refer to a registry proof. Individual behavior
	// remains bound through member.HitIDs and request.Hits, as in verifiedGroup.
	g.SourceIDs = []string{"group-registry-proof"}
	if text = providerGroupMemberSummary(g, m, hits); !strings.Contains(text, "通信观测5条") {
		t.Fatal("valid member sources were mistaken for missing group proof", text)
	}
	delete(hits, "h0")
	if text = providerGroupMemberSummary(g, m, hits); !strings.Contains(text, "实际行为来源绑定不足") || strings.Contains(text, "目的端点示例") {
		t.Fatal("missing source was trusted", text)
	}
}

func TestProviderGroupSummaryRejectsWrongOwnerAndIncompleteGroup(t *testing.T) {
	at := time.Now().UTC()
	scope := evidence.Scope{AssetID: "a", DeviceID: "d", EndpointID: "udp://198.51.100.20:53"}
	m := evidence.GroupMember{AssetID: "a", Scope: scope, HitIDs: []string{"h"}, MembershipVerified: true}
	g := evidence.GroupInput{Window: evidence.AnalysisWindow{Start: at, End: at.Add(time.Minute)}, Provenance: evidence.Provenance{Verified: true, Complete: true, Version: "test", SourceIDs: []string{"h"}}, DNS: []evidence.DNSRecord{{SourceID: "h", Time: at, Domain: "foreign-owner.example"}}, DNSOwnership: map[string]string{"h": "b"}}
	hits := map[string]evidence.Hit{"h": {ID: "h", Scope: scope, OccurredAt: at}}
	if text := providerGroupMemberSummary(g, m, hits); strings.Contains(text, "foreign-owner.example") || !strings.Contains(text, "实际行为未提供或未核验") {
		t.Fatal(text)
	}
	g.Complete = false
	if text := providerGroupMemberSummary(g, m, hits); strings.Contains(text, "目的端点示例") || !strings.Contains(text, "实际行为未提供或未核验") {
		t.Fatal(text)
	}
}
