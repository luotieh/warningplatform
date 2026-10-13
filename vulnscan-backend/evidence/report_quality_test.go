package evidence

import (
	"context"
	"testing"
)

func TestReportTimelineOptInPreservesPacketQualityAndDefault(t *testing.T) {
	r, c := fullFixture(BeaconPeriodic)
	r.Facts = []FactID{BeaconPeriodic}
	r.Quality.CaptureTruncated = nil
	e, err := NewEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	before, err := e.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if before.Findings[0].ReasonCode != UnverifiedCoverage {
		t.Fatal("default caller behavior changed")
	}
	complete := true
	r.Quality.SavedTimelineComplete = &complete
	after, err := e.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if after.Findings[0].Status != Observed {
		t.Fatal("verified saved timeline was blocked by packet completeness", after.Findings[0])
	}
	if r.Quality.CaptureTruncated != nil {
		t.Fatal("packet quality overwritten")
	}
}
