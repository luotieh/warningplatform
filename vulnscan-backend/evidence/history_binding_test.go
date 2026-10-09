package evidence

import (
	"math"
	"strings"
	"testing"
)

func boundHistoryFinding(t *testing.T, r Request, c Config) Finding {
	t.Helper()
	e, err := NewEngine(c)
	if err != nil {
		t.Fatal(err)
	}
	result := evaluate(t, e, r)
	if len(result.Findings) != 1 {
		t.Fatalf("unexpected findings: %+v", result)
	}
	return result.Findings[0]
}

func TestStageProgressionRequiresCurrentBoundStage(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HistoryData)
		want   Status
		reason ReasonCode
	}{
		{"current_advances", func(h *HistoryData) {}, Observed, ConditionsMet},
		{"current_same_as_latest", func(h *HistoryData) { h.CurrentStage = "c2" }, NotObserved, ConditionsNotMet},
		{"current_regresses", func(h *HistoryData) { h.CurrentStage = "scan" }, NotObserved, ConditionsNotMet},
		{"missing_current", func(h *HistoryData) { h.CurrentStage = "" }, Missing, MissingInput},
		{"unknown_current", func(h *HistoryData) { h.CurrentStage = "success" }, Missing, MissingInput},
		{"llm_current", func(h *HistoryData) { h.CurrentStageSource = "llm" }, Missing, MissingInput},
		{"unverified_current", func(h *HistoryData) { h.CurrentStageProvenance.Verified = false }, Missing, MissingInput},
		{"partial_current", func(h *HistoryData) { h.CurrentStageProvenance.Complete = false }, Missing, MissingInput},
		{"current_without_sources", func(h *HistoryData) { h.CurrentStageProvenance.SourceIDs = nil }, Missing, MissingInput},
		{"current_without_version", func(h *HistoryData) { h.CurrentStageProvenance.Version = "" }, Missing, MissingInput},
		{"same_asset_other_ioc", func(h *HistoryData) {
			for i := range h.Events {
				h.Events[i].IOC = "other-ioc"
			}
		}, NotObserved, ConditionsNotMet},
		{"other_asset_same_ioc", func(h *HistoryData) {
			for i := range h.Events {
				h.Events[i].AssetID = "other-asset"
			}
		}, NotObserved, ConditionsNotMet},
		{"missing_ioc_identity", func(h *HistoryData) { h.IOC = "" }, Missing, UnresolvedBinding},
		{"unknown_historical_identity", func(h *HistoryData) { h.Events[0].IOC = "" }, Missing, UnresolvedBinding},
		{"mismatched_current_endpoint", func(h *HistoryData) { h.Endpoint = "other-endpoint" }, Missing, UnresolvedBinding},
		{"unreviewed_relevant_history", func(h *HistoryData) { h.Events[0].Adjudication = "unreviewed" }, Missing, MissingInput},
		{"false_positive_history_not_attack", func(h *HistoryData) {
			for i := range h.Events {
				h.Events[i].Adjudication = "false_positive"
			}
		}, NotObserved, ConditionsNotMet},
		{"unknown_historical_stage", func(h *HistoryData) { h.Events[0].Stage = "unknown" }, Missing, MissingInput},
		{"missing_historical_stage", func(h *HistoryData) { h.Events[0].Stage = "" }, Missing, MissingInput},
		{"historical_regression", func(h *HistoryData) { h.Events[0].Stage = "c2"; h.Events[1].Stage = "scan" }, NotObserved, ConditionsNotMet},
		{"same_time_ambiguous_stages", func(h *HistoryData) { h.Events[1].Time = h.Events[0].Time }, Missing, UnresolvedBinding},
		{"same_time_same_level", func(h *HistoryData) { h.Events[1].Time = h.Events[0].Time; h.Events[1].Stage = "exploit" }, Observed, ConditionsMet},
		{"one_history_plus_current", func(h *HistoryData) { h.Events = h.Events[:1]; h.CurrentStage = "c2" }, Observed, ConditionsMet},
		{"no_history", func(h *HistoryData) { h.Events = nil }, NotObserved, ConditionsNotMet},
		{"unrelated_invalid_stage_ignored", func(h *HistoryData) { h.Events[0].IOC = "other-ioc"; h.Events[0].Stage = "unknown" }, Observed, ConditionsMet},
		{"mixed_historical_campaigns_without_current_campaign", func(h *HistoryData) {
			for i := range h.Events {
				h.Events[i].CampaignID = h.Events[i].ID
				h.Events[i].CampaignProvenance = fixtureProvenance()
			}
		}, Missing, UnresolvedBinding},
		{"unverified_historical_campaign_on_same_ioc", func(h *HistoryData) { h.Events[0].CampaignID = "unverified-campaign" }, Missing, UnresolvedBinding},
		{"benign_history_with_missing_identity_does_not_supply_stage", func(h *HistoryData) {
			h.Events[0].Adjudication = "false_positive"
			h.Events[0].IOC = ""
			h.Events[0].Stage = ""
		}, Observed, ConditionsMet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := fullFixture("F_HIST_STAGE_PROGRESSION")
			tc.change(r.Inputs[0].History)
			f := boundHistoryFinding(t, r, c)
			if f.Status != tc.want || f.ReasonCode != tc.reason {
				t.Fatalf("want %s/%s got %+v", tc.want, tc.reason, f)
			}
		})
	}
}

func bindStageCampaign(h *HistoryData) {
	h.CampaignID = "campaign"
	h.CampaignProvenance = fixtureProvenance()
	for i := range h.Events {
		h.Events[i].CampaignID = h.CampaignID
		h.Events[i].CampaignProvenance = fixtureProvenance()
	}
}

func TestStageCampaignProofAndConflicts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HistoryData)
		want   Status
		reason ReasonCode
	}{
		{"verified_campaign_rotates_ioc", func(h *HistoryData) {
			h.IOC = "current-ioc"
			for i := range h.Events {
				h.Events[i].IOC = "old-ioc"
			}
		}, Observed, ConditionsMet},
		{"campaign_without_ioc", func(h *HistoryData) {
			h.IOC = ""
			for i := range h.Events {
				h.Events[i].IOC = ""
			}
		}, Observed, ConditionsMet},
		{"other_campaign_same_ioc", func(h *HistoryData) {
			for i := range h.Events {
				h.Events[i].CampaignID = "other-campaign"
			}
		}, NotObserved, ConditionsNotMet},
		{"unverified_current_campaign", func(h *HistoryData) { h.CampaignProvenance.Verified = false }, Missing, UnresolvedBinding},
		{"missing_current_campaign_sources", func(h *HistoryData) { h.CampaignProvenance.SourceIDs = nil }, Missing, UnresolvedBinding},
		{"missing_historical_campaign", func(h *HistoryData) { h.Events[0].CampaignID = "" }, Missing, UnresolvedBinding},
		{"unverified_historical_campaign", func(h *HistoryData) { h.Events[0].CampaignProvenance.Verified = false }, Missing, UnresolvedBinding},
		{"partial_historical_campaign", func(h *HistoryData) { h.Events[0].CampaignProvenance.Complete = false }, Missing, UnresolvedBinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := fullFixture("F_HIST_STAGE_PROGRESSION")
			h := r.Inputs[0].History
			bindStageCampaign(h)
			tc.change(h)
			f := boundHistoryFinding(t, r, c)
			if f.Status != tc.want || f.ReasonCode != tc.reason {
				t.Fatalf("want %s/%s got %+v", tc.want, tc.reason, f)
			}
		})
	}
}

func TestCoordinationParameterInfrastructureAndCampaignBinding(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HistoryData)
		want   Status
		reason ReasonCode
	}{
		{"bound_parameter_match", func(h *HistoryData) {}, Observed, ConditionsMet},
		{"ioc_conflict_even_same_endpoint", func(h *HistoryData) { h.Events[0].IOC = "other-ioc" }, NotObserved, ConditionsNotMet},
		{"endpoint_conflict_even_same_ioc", func(h *HistoryData) { h.Events[0].Endpoint = "other-endpoint" }, NotObserved, ConditionsNotMet},
		{"other_campaign_same_parameters", func(h *HistoryData) { h.Events[0].CampaignID = "other-campaign" }, NotObserved, ConditionsNotMet},
		{"different_asset", func(h *HistoryData) { h.Events[0].AssetID = "other-asset" }, NotObserved, ConditionsNotMet},
		{"historical_group_not_asset_scope", func(h *HistoryData) { h.Events[0].GroupID = "other-group" }, NotObserved, ConditionsNotMet},
		{"no_concrete_infrastructure", func(h *HistoryData) { h.IOC = ""; h.Endpoint = ""; h.Family = "same-family" }, Missing, UnresolvedBinding},
		{"unknown_historical_ioc", func(h *HistoryData) { h.Events[0].IOC = "" }, Missing, UnresolvedBinding},
		{"unknown_historical_endpoint", func(h *HistoryData) { h.Events[0].Endpoint = "" }, Missing, UnresolvedBinding},
		{"missing_current_campaign", func(h *HistoryData) { h.CampaignID = "" }, Missing, UnresolvedBinding},
		{"unverified_current_campaign", func(h *HistoryData) { h.CampaignProvenance.Verified = false }, Missing, UnresolvedBinding},
		{"missing_historical_campaign", func(h *HistoryData) { h.Events[0].CampaignID = "" }, Missing, UnresolvedBinding},
		{"unverified_historical_campaign", func(h *HistoryData) { h.Events[0].CampaignProvenance.Verified = false }, Missing, UnresolvedBinding},
		{"missing_campaign_sources", func(h *HistoryData) { h.Events[0].CampaignProvenance.SourceIDs = nil }, Missing, UnresolvedBinding},
		{"wrong_current_endpoint", func(h *HistoryData) { h.Endpoint = "other-endpoint" }, Missing, UnresolvedBinding},
		{"nonmatching_parameters", func(h *HistoryData) { h.Events[0].Parameters["phase"] = 100 }, NotObserved, ConditionsNotMet},
		{"missing_historical_parameter", func(h *HistoryData) { h.Events[0].Parameters = map[string]float64{"unrelated": 60} }, Missing, MissingInput},
		{"nonfinite_current_parameter", func(h *HistoryData) { h.CurrentParameters["phase"] = math.NaN() }, Missing, MissingInput},
		{"nonfinite_historical_parameter", func(h *HistoryData) { h.Events[0].Parameters["phase"] = math.Inf(1) }, Missing, MissingInput},
		{"unreviewed_bound_history", func(h *HistoryData) { h.Events[0].Adjudication = "unreviewed" }, Missing, MissingInput},
		{"endpoint_only_identity", func(h *HistoryData) { h.IOC = ""; h.Events[0].IOC = "" }, Observed, ConditionsMet},
		{"ioc_only_identity", func(h *HistoryData) { h.Endpoint = ""; h.Events[0].Endpoint = "" }, Observed, ConditionsMet},
		{"no_historical_records", func(h *HistoryData) { h.Events = nil }, NotObserved, ConditionsNotMet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := fullFixture("F_HIST_COORD_PARAM_MATCH")
			tc.change(r.Inputs[0].History)
			f := boundHistoryFinding(t, r, c)
			if f.Status != tc.want || f.ReasonCode != tc.reason {
				t.Fatalf("want %s/%s got %+v", tc.want, tc.reason, f)
			}
		})
	}
}

func bindCoordinationGroup(h *HistoryData, asset string) {
	h.GroupID = "group"
	h.GroupMembershipVerified = true
	h.CurrentMemberIDs = []string{asset, "member2", "member3"}
	for i := range h.Events {
		h.Events[i].GroupID = h.GroupID
		h.Events[i].MemberIDs = append([]string(nil), h.CurrentMemberIDs...)
		h.Events[i].GroupMembershipVerified = true
	}
}

func TestCoordinationParameterCompleteGroupMembership(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HistoryData)
		want   Status
		reason ReasonCode
	}{
		{"same_complete_group", func(h *HistoryData) {}, Observed, ConditionsMet},
		{"member_order_irrelevant", func(h *HistoryData) { m := h.Events[0].MemberIDs; m[0], m[2] = m[2], m[0] }, Observed, ConditionsMet},
		{"same_group_replaced_member", func(h *HistoryData) { h.Events[0].MemberIDs[2] = "new-member" }, NotObserved, ConditionsNotMet},
		{"same_group_extra_member", func(h *HistoryData) { h.Events[0].MemberIDs = append(h.Events[0].MemberIDs, "extra-member") }, NotObserved, ConditionsNotMet},
		{"other_group_same_members", func(h *HistoryData) { h.Events[0].GroupID = "other-group" }, NotObserved, ConditionsNotMet},
		{"partial_historical_members", func(h *HistoryData) { h.Events[0].MemberIDs = h.Events[0].MemberIDs[:2] }, Missing, UnresolvedBinding},
		{"duplicate_historical_members", func(h *HistoryData) { h.Events[0].MemberIDs[2] = h.Events[0].MemberIDs[1] }, Missing, UnresolvedBinding},
		{"blank_historical_member", func(h *HistoryData) { h.Events[0].MemberIDs[1] = " " }, Missing, UnresolvedBinding},
		{"unverified_historical_members", func(h *HistoryData) { h.Events[0].GroupMembershipVerified = false }, Missing, UnresolvedBinding},
		{"unverified_current_members", func(h *HistoryData) { h.GroupMembershipVerified = false }, Missing, UnresolvedBinding},
		{"partial_current_members", func(h *HistoryData) { h.CurrentMemberIDs = h.CurrentMemberIDs[:2] }, Missing, UnresolvedBinding},
		{"duplicate_current_members", func(h *HistoryData) { h.CurrentMemberIDs[2] = h.CurrentMemberIDs[1] }, Missing, UnresolvedBinding},
		{"current_asset_outside_group", func(h *HistoryData) { h.CurrentMemberIDs[0] = "different-asset" }, Missing, UnresolvedBinding},
		{"historical_asset_outside_declared_group", func(h *HistoryData) { h.Events[0].AssetID = "outsider" }, Missing, UnresolvedBinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := fullFixture("F_HIST_COORD_PARAM_MATCH")
			h := r.Inputs[0].History
			bindCoordinationGroup(h, r.Hits[0].Scope.AssetID)
			tc.change(h)
			f := boundHistoryFinding(t, r, c)
			if f.Status != tc.want || f.ReasonCode != tc.reason {
				t.Fatalf("want %s/%s got %+v", tc.want, tc.reason, f)
			}
		})
	}
}

func TestBoundHistoryTraceExcludesUnrelatedEvents(t *testing.T) {
	for _, id := range []FactID{"F_HIST_STAGE_PROGRESSION", "F_HIST_COORD_PARAM_MATCH"} {
		t.Run(string(id), func(t *testing.T) {
			r, c := fullFixture(id)
			h := r.Inputs[0].History
			unrelated := h.Events[0]
			unrelated.ID = "unrelated-event"
			unrelated.AdjudicationID = "unrelated-review"
			unrelated.IOC = "other-ioc"
			unrelated.Stage = "unknown"
			h.Events = append(h.Events, unrelated)
			if id == "F_HIST_STAGE_PROGRESSION" {
				h.CurrentStageProvenance.SourceIDs = []string{"current-stage-proof"}
				h.CurrentStageProvenance.Version = "verified-stage-v2"
			} else {
				h.CampaignProvenance.SourceIDs = []string{"current-campaign-proof"}
				h.Events[0].CampaignProvenance.SourceIDs = []string{"historical-campaign-proof"}
			}
			f := boundHistoryFinding(t, r, c)
			if f.Status != Observed {
				t.Fatalf("valid evidence rejected: %+v", f)
			}
			refs := strings.Join(f.SourceIDs, "|")
			if strings.Contains(refs, "unrelated-event") || strings.Contains(refs, "unrelated-review") {
				t.Fatal("unrelated rows included as support")
			}
			if id == "F_HIST_STAGE_PROGRESSION" && !strings.Contains(refs, "current-stage-proof") {
				t.Fatal("current stage proof missing")
			}
			if id == "F_HIST_COORD_PARAM_MATCH" && (!strings.Contains(refs, "current-campaign-proof") || !strings.Contains(refs, "historical-campaign-proof")) {
				t.Fatal("campaign proofs missing")
			}
			if len(f.Limitations) == 0 {
				t.Fatal("causal interpretation limit missing")
			}
		})
	}
}

func TestCoordinationParameterFalsePositiveRecordedSeparately(t *testing.T) {
	r, c := fullFixture("F_HIST_COORD_PARAM_MATCH")
	r.Inputs[0].History.Events[0].Adjudication = "false_positive"
	f := boundHistoryFinding(t, r, c)
	if f.Status != Observed || f.Measurements.Values["false_positive_parameter_matches"] != 1 || f.Measurements.Values["malicious_parameter_matches"] != 0 {
		t.Fatalf("false-positive history misrepresented: %+v", f)
	}
}
