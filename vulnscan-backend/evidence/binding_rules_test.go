package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestPartitionedFanoutAndInvalidHandoff(t *testing.T) {
	r, c := groupFixture("F_COORD_FANOUT")
	x := &r.Groups[0]
	start := x.Window.Start
	x.Connections = nil
	c.Policies["F_COORD_FANOUT"] = map[string]float64{"handoff_seconds": 10}
	for asset, m := range x.Members {
		for j := 0; j < 2; j++ {
			x.Connections = append(x.Connections, Connection{SourceID: string(rune('a' + asset*2 + j)), AssetID: m.AssetID, Destination: "203.0.113." + stringPort(uint16(asset*2+j+1)), Time: start.Add(time.Duration(asset*5+j) * time.Second), Port: 22})
		}
	}
	e, err := NewEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	if evaluate(t, e, r).Findings[0].Status != Observed {
		t.Fatal("verified contiguous partition not detected")
	}
	x.Connections[4].Time = start.Add(time.Second)
	x.Connections[5].Time = start.Add(2 * time.Second)
	if evaluate(t, e, r).Findings[0].Status != NotObserved {
		t.Fatal("overlapping handoff accepted")
	}
}

func TestScopedAuthorizationCannotCoverUnregisteredTarget(t *testing.T) {
	r, c := fullFixture("F_EXCL_SCAN_TASK")
	r.Inputs[0].Network.Connections[0].Destination = "198.51.100.1"
	e, _ := NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != NotObserved {
		t.Fatal("registered role treated as authorization for other targets")
	}
	r, c = fullFixture("F_HIST_EXERCISE")
	a := &r.Inputs[0].Authorizations.Records[0]
	a.Endpoint = ""
	a.Domains = []string{"example.com"}
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Observed {
		t.Fatal("verified exercise domain not matched")
	}
	r.Inputs[0].HTTP.Records[0].URL = "https://other.com/"
	if evaluate(t, e, r).Findings[0].Status != NotObserved {
		t.Fatal("exercise mixed with unregistered domain")
	}
}

func TestBaselinePolicyAndSourceVersions(t *testing.T) {
	r, c := fullFixture("F_RATE_BURST")
	e, _ := NewEngine(c)
	f := evaluate(t, e, r).Findings[0]
	if len(f.Dependencies) != 1 || f.Dependencies[0].Kind != "baseline" || f.Dependencies[0].Version != "synthetic-fixture-v1" {
		t.Fatalf("baseline version lost: %+v", f.Dependencies)
	}
	r.Inputs[0].Baselines[0].Verified = false
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unverified baseline used")
	}
	r, c = fullFixture("F_DNS_HIGH_ENTROPY")
	r.Inputs[0].Baselines[0].Metrics["unique_subdomain_ratio_p95"] = -1
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("negative ratio accepted")
	}
	c = DefaultConfig()
	c.Policies = map[FactID]map[string]float64{"F_RATE_RAMP": {"invented_policy": 1}}
	if _, err := NewEngine(c); err == nil {
		t.Fatal("unknown policy accepted")
	}
}

func TestHistoricalGapsAndUnknownMembership(t *testing.T) {
	r, c := fullFixture("F_HIST_INFRA_PERSISTENCE")
	r.Inputs[0].History.Events[0].Time = r.Inputs[0].History.AsOf.AddDate(0, 0, -5)
	e, _ := NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != NotObserved {
		t.Fatal("nonconsecutive dates described as continuous")
	}
	r, c = fullFixture("F_HIST_GROUP_RECURRENCE")
	r.Inputs[0].History.GroupMembershipVerified = false
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unknown current group membership accepted")
	}
	r, c = fullFixture("F_LONG_LOW_SESSION")
	r.Inputs[0].Network.Sessions[0].HitIDs = []string{"unknown-hit"}
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unresolved session join treated as negative")
	}
}

func TestDERCertificateVerification(t *testing.T) {
	r, c := fullFixture("F_TLS_CERT_ANOMALY")
	d := r.Inputs[0].TLS
	record := &d.Records[0]
	now := record.Time
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other.com"}, DNSNames: []string{"other.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	record.CertificatesDER = [][]byte{leafDER}
	record.ChainVerified = false
	record.NotBefore = time.Time{}
	record.NotAfter = time.Time{}
	record.Issuer = ""
	d.TrustRootsDER = [][]byte{rootDER}
	d.TrustedIssuers = []string{"CN=synthetic-root"}
	e, _ := NewEngine(c)
	if f := evaluate(t, e, r).Findings[0]; f.Status != NotObserved {
		t.Fatalf("valid explicit-root chain rejected: %+v", f)
	}
	record.Time = now.Add(2 * time.Hour)
	if evaluate(t, e, r).Findings[0].Status != Observed {
		t.Fatal("expired DER chain not detected")
	}
	record.CertificatesDER = [][]byte{{1, 2, 3}}
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("invalid DER produced unsupported verdict")
	}
}

func TestVerifiedDomainPatternAndDeclaredBrand(t *testing.T) {
	r, c := groupFixture("F_SHARED_DOMAIN_CLUSTER")
	x := &r.Groups[0]
	x.DomainPatternsVerified = true
	x.DomainPatterns = []DomainPattern{{ID: "campaign", Expression: `^campaign[0-9]+\.com$`}}
	x.Baselines[0].Frequencies = map[string]float64{}
	for j := range x.DNS {
		domain := "campaign" + stringPort(uint16(j+1)) + ".com"
		x.DNS[j].Domain = domain
		x.Baselines[0].Frequencies[domain] = 0.001
	}
	e, _ := NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Observed {
		t.Fatal("audited naming pattern not associated")
	}
	x.DomainPatternsVerified = false
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unverified pattern used")
	}
	r, c = fullFixture("F_BRAND_IMPOSTOR")
	r.Inputs[0].HTTP.Records[0].URL = "https://unrelated.com/"
	r.Inputs[0].HTTP.Records[0].DeclaredBrand = "example"
	r.Inputs[0].HTTP.Records[0].BrandClaimVerified = true
	e, _ = NewEngine(c)
	if evaluate(t, e, r).Findings[0].Status != Observed {
		t.Fatal("verified brand/domain authorization conflict not found")
	}
	r.Inputs[0].HTTP.Records[0].BrandClaimVerified = false
	if evaluate(t, e, r).Findings[0].Status != Missing {
		t.Fatal("unverified brand claim used")
	}
}

func TestConcurrentRichRuleInputsRemainImmutable(t *testing.T) {
	for _, id := range SupportedFacts() {
		t.Run(string(id), func(t *testing.T) {
			r, c := fullFixture(id)
			before, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			e, err := NewEngine(c)
			if err != nil {
				t.Fatal(err)
			}
			expected := evaluate(t, e, r)
			var wg sync.WaitGroup
			for j := 0; j < 4; j++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					out, err := e.Evaluate(context.Background(), r)
					if err != nil || !reflect.DeepEqual(out, expected) {
						t.Errorf("shared-input result changed: %v", err)
					}
				}()
			}
			wg.Wait()
			after, _ := json.Marshal(r)
			if string(before) != string(after) {
				t.Fatal("rule mutated caller input")
			}
		})
	}
}
