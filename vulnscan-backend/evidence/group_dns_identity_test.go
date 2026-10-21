package evidence

import "testing"

func TestGroupDNSIndependentLogSourcesRemainSupported(t *testing.T) {
	r, c := groupFixture("F_GROUP_NXDOMAIN_CLUSTER")
	for _, row := range r.Groups[0].DNS {
		for _, hit := range r.Hits {
			if row.SourceID == hit.ID {
				t.Fatal("fixture must exercise independent DNS log provenance")
			}
		}
	}
	if f := contractFinding(t, r, c); f.Status != Observed {
		t.Fatalf("independent DNS log rejected: %+v", f)
	}
}

func TestGroupDNSRepeatedFailureCannotInflateRate(t *testing.T) {
	for _, repeated := range []bool{false, true} {
		r, c := groupFixture("F_GROUP_NXDOMAIN_CLUSTER")
		g := &r.Groups[0]
		g.Baselines[0].Metrics["group_nxdomain_rate_p99"] = 0.75
		original := append([]DNSRecord(nil), g.DNS...)
		for _, row := range original {
			success := row
			success.SourceID += "-success"
			success.RCode = 0
			g.DNSOwnership[success.SourceID] = g.DNSOwnership[row.SourceID]
			g.DNS = append(g.DNS, success)
			if repeated {
				for i := 0; i < 9; i++ {
					g.DNS = append(g.DNS, row)
				}
			}
		}
		f := contractFinding(t, r, c)
		if !repeated && f.Status != NotObserved {
			t.Fatalf("unique failure rate must remain 1/2: %+v", f)
		}
		if repeated && (f.Status != Missing || f.ReasonCode != UnresolvedBinding) {
			t.Fatalf("repeated source inflated or silently altered rate: %+v", f)
		}
	}
}

func TestEveryGroupRuleRejectsDuplicateDNSIdentity(t *testing.T) {
	for _, id := range SupportedFacts() {
		if !groupRule(id) {
			continue
		}
		for _, conflict := range []bool{false, true} {
			t.Run(string(id)+map[bool]string{false: "/identical", true: "/conflict"}[conflict], func(t *testing.T) {
				r, c := groupFixture(id)
				g := &r.Groups[0]
				row := DNSRecord{SourceID: "independent-dns", Time: g.Window.Start, Domain: "example.com", RCode: 3, RCodeKnown: true}
				g.DNSOwnership[row.SourceID] = g.Members[0].AssetID
				g.DNS = append(g.DNS, row)
				if conflict {
					row.RCode = 0
					row.Domain = "other.example.com"
				}
				g.DNS = append(g.DNS, row)
				if f := contractFinding(t, r, c); f.Status != Missing || f.ReasonCode != UnresolvedBinding {
					t.Fatalf("duplicate group DNS source accepted: %+v", f)
				}
			})
		}
	}
}
