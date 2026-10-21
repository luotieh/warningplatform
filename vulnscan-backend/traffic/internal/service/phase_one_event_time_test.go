package service

import (
	"context"
	"fmt"
	"testing"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

func TestEventTimeDeduplicatesEventsWithoutFillingDurationOrUsingPeers(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "tcp://203.0.113.1:443"}
	binding := evidence.PhaseOneBinding{Scope: scope, IOCType: "ip", IOCValue: "203.0.113.1", Verified: true}
	peer := binding
	peer.Scope.AssetID = "peer"
	m := PhaseOneMaterials{Bindings: []evidence.PhaseOneBinding{binding, peer}, CurrentBindings: []evidence.PhaseOneBinding{binding}, Expanded: true}
	snap := EvidenceSnapshot{EventID: "current", Version: 1, Sources: []string{"current", "merged-source"}, Context: map[string]any{"first_time": at.Format(time.RFC3339)}}
	row := ReportHistoryRow{EventID: "prior", DeviceID: scope.DeviceID, AllAssetIDs: []string{scope.AssetID}, IOCs: []domain.IOC{{Type: "ip", Value: binding.IOCValue}}, First: at.AddDate(0, 0, -7), Last: at.AddDate(0, 0, -1)}
	h := ReportHistory{Status: "available", EventSummaryOnly: true, EventSummaryComplete: true, Start: at.AddDate(0, 0, -30), End: at, Rows: []ReportHistoryRow{row, row}}
	excluded := row
	excluded.EventID = "merged-source"
	h.Rows = append(h.Rows, excluded)
	foreign := row
	foreign.EventID = "foreign"
	foreign.AllAssetIDs = []string{"other-asset"}
	h.Rows = append(h.Rows, foreign)
	findings, err := phaseOneEventTimeFacts(context.Background(), snap, m, h, []evidence.FactID{"F_FIXED_DAILY_WINDOW", evidence.MultiDayPersist})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatal("peer binding created a current event", findings)
	}
	for _, f := range findings {
		if f.Measurements.SampleCount != 2 || len(f.SourceIDs) != 2 {
			t.Fatal("duplicate event or event duration inflated samples", f)
		}
		if f.FactID == "F_FIXED_DAILY_WINDOW" && f.ReasonCode != evidence.InsufficientSamples {
			t.Fatal("seven-day event span supplied extra days", f)
		}
		if f.FactID == evidence.MultiDayPersist && (f.Measurements.DaysActive == nil || *f.Measurements.DaysActive != 2) {
			t.Fatal("duration was expanded to active days", f)
		}
	}
	// An invalid current timestamp cannot be repaired by valid historical dates.
	snap.Context["first_time"] = "invalid"
	findings, err = phaseOneEventTimeFacts(context.Background(), snap, m, h, []evidence.FactID{"F_FIXED_DAILY_WINDOW"})
	if err != nil || len(findings) != 1 || findings[0].ReasonCode != evidence.InvalidTime {
		t.Fatal("invalid current event time accepted", findings, err)
	}
}

func TestJitterNeverUsesMergedHistoryOrPeerContacts(t *testing.T) {
	at := time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)
	scope := evidence.Scope{AssetID: "asset", DeviceID: "device", EndpointID: "endpoint"}
	binding := evidence.PhaseOneBinding{Scope: scope, IOCType: "ip", IOCValue: "203.0.113.1", Verified: true}
	m := PhaseOneMaterials{Bindings: []evidence.PhaseOneBinding{binding}, Expanded: true, CurrentComplete: true, Complete: true}
	for i := 0; i < 25; i++ {
		event := "historical-or-peer"
		if i == 0 {
			event = "current"
		}
		m.Contacts = append(m.Contacts, PhaseOneContact{ID: fmt.Sprint(i), HitID: fmt.Sprint(i), Time: at.Add(time.Duration(i) * time.Minute), Kind: "tcp_initiation", Scope: scope, IOCType: binding.IOCType, IOCValue: binding.IOCValue, Snapshot: PhaseOneSnapshotSource{EventID: event}})
	}
	snap := EvidenceSnapshot{EventID: "current", Version: 1, Context: map[string]any{"first_time": at.Format(time.RFC3339)}}
	fs, err := computePhaseOneFacts(context.Background(), snap, m, m, ReportHistory{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.FactID == "F_BEACON_JITTER" {
			found = true
			if f.Measurements.SampleCount != 1 || f.ReasonCode != evidence.InsufficientSamples {
				t.Fatal("cross-event jitter backfill", f)
			}
		}
	}
	if !found {
		t.Fatal("jitter outcome absent")
	}
}
