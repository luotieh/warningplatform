package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func providerHistorySubjectsFixture(t *testing.T) (EvidenceCollection, PreparedEvidenceBundle) {
	t.Helper()
	s := phaseOneFixture(t)
	at := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	_, err := s.Store.CreateAsset(domain.Asset{ID: "asset-b", Address: "192.0.2.2", Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	messages := []map[string]any{}
	for i, ioc := range []domain.IOC{{Type: "ip", Value: "203.0.113.2"}, {Type: "domain", Value: "agent.test"}, {Type: "url", Value: "http://agent.test/agent"}} {
		m := providerTemporalMessage(t, at.Add(time.Duration(i)*time.Second), uint32(100+i*100))
		// Retain actual wire fields for fixture installation but use summary
		// input so independent contacts and protocol completeness are not implied.
		m["ioc"] = map[string]any{"ioc_type": ioc.Type, "ioc_value": ioc.Value}
		m["raw_packet"].(map[string]any)["packet_hex"] = ""
		messages = append(messages, m)
	}
	phaseOneInstallSnapshot(t, s, "current", 1, messages)
	for i, typ := range []string{"ip", "domain", "url"} {
		for day, address := range []string{"192.0.2.1", "192.0.2.2"} {
			when := at.AddDate(0, 0, -day-1)
			m := map[string]any{"device_id": fmt.Sprintf("historical-sensor-%d", day), "src_ip": address, "dst_ip": "203.0.113.2", "first_time": when.Format(time.RFC3339Nano), "last_time": when.Format(time.RFC3339Nano), "ioc": map[string]any{"ioc_type": typ, "ioc_value": []string{"203.0.113.2", "agent.test", "http://agent.test/agent"}[i]}, "app": map[string]any{"http_url": "http://agent.test/agent"}}
			if typ == "url" {
				m["device_id"] = ""
			} // explicitly unbound historical material
			raw, _ := json.Marshal(m)
			if _, err := s.Store.CreateEvent(domain.Event{EventID: fmt.Sprintf("%s-past-%d", typ, day), Context: string(raw), CreatedAt: when, LastSeenAt: &when}); err != nil {
				t.Fatal(err)
			}
		}
	}
	c, err := CollectEvidenceFromPlatform(context.Background(), s.Store.(store.EvidenceReader), "current", providerTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := PreprocessCollectedEvidence(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return c, b
}

func TestProviderHistorySubjectsCollectPreprocessWireAndExecute(t *testing.T) {
	c, b := providerHistorySubjectsFixture(t)
	if len(c.HistorySnapshots) != 0 || len(b.Inputs.PlatformHistorySubjects) != 1 {
		t.Fatal("extra historical read or subjects missing")
	}
	for _, ss := range b.Inputs.PlatformHistorySubjects {
		if len(ss) != 3 {
			t.Fatal("lost IP/domain/url", ss)
		}
	}
	var encoded bytes.Buffer
	if err := EncodePreparedEvidence(&encoded, b); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePreparedEvidence(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if digest(decoded.Inputs.PlatformHistorySubjects) != digest(b.Inputs.PlatformHistorySubjects) {
		t.Fatal("wire lost subjects")
	}
	out, err := ExecutePreparedEvidence(context.Background(), decoded, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]evidence.Finding{}
	for _, f := range out.Evaluation.Result.Findings {
		if f.FactID == "F_HIST_INFRA_PERSISTENCE" {
			seen[f.IOCType] = f
		}
	}
	if len(seen) != 3 || seen["ip"].Status != evidence.Observed || seen["domain"].Status != evidence.Observed || seen["url"].Status != evidence.Missing {
		t.Fatal("wrong exact IOC execution", seen)
	}
	normalizedInfra := 0
	for _, item := range out.Evidence.Normalized.Items {
		if item.Kind == "fact" && item.IOCType != "" && item.ExecutionStatus == "" {
			t.Fatal("pipeline lost exact IOC execution metadata", item)
		}
		if item.RuleID == "F_HIST_INFRA_PERSISTENCE" {
			normalizedInfra++
			if item.ExecutionStatus != "executed" {
				t.Fatal("pipeline changed per-subject execution status", item)
			}
		}
	}
	if normalizedInfra != 3 {
		t.Fatal("pipeline normalization lost exact subjects", normalizedInfra)
	}
	for typ, f := range seen {
		if typ == "url" {
			continue
		}
		if f.Measurements.Values["distinct_assets"] != 2 || f.Measurements.Values["consecutive_days"] != 2 || f.Measurements.SampleCount != 1 {
			t.Fatal("cross subject denominator", f)
		}
		for _, id := range f.SourceIDs {
			if strings.Contains(id, "-past-") && !strings.HasPrefix(id, typ+"-past-") {
				t.Fatal("foreign IOC history reference", f)
			}
		}
	}
	changed := decoded
	for key, ss := range changed.Inputs.PlatformHistorySubjects {
		ss[0].History.Version += "-new-source-revision"
		changed.Inputs.PlatformHistorySubjects[key] = ss
		break
	}
	if changed.Validate() == nil {
		t.Fatal("subject mutation did not invalidate bundle digest")
	}
	changed.Coverage = PreparedInputCoverage(changed.Inputs)
	changed.Seal()
	out2, err := ExecutePreparedEvidence(context.Background(), changed, PreparedExecutionOptions{SemanticMode: PreparedSemanticDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if out2.Evaluation.InputDigest == out.Evaluation.InputDigest {
		t.Fatal("actual typed subject changed without invalidating algorithm input digest")
	}
}

func TestProviderHistorySubjectsRejectUnbackedCurrentBinding(t *testing.T) {
	_, b := providerHistorySubjectsFixture(t)
	for key, ss := range b.Inputs.PlatformHistorySubjects {
		ss[0].CurrentSourceIDs = []string{b.Inputs.Request.Hits[len(b.Inputs.Request.Hits)-1].ID}
		b.Inputs.PlatformHistorySubjects[key] = ss
		break
	}
	b.Seal()
	if err := b.Validate(); err == nil {
		t.Fatal("source that does not support IOC accepted")
	}
}
