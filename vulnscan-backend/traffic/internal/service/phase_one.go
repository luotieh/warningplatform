package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
)

type PhaseOneEvaluation struct {
	Facts     []evidence.Finding      `json:"facts"`
	Result    evidence.PhaseOneResult `json:"result"`
	Materials PhaseOneMaterials       `json:"materials"`
	CacheKey  string                  `json:"cache_key"`
	CacheHit  bool                    `json:"cache_hit"`
	Persisted bool                    `json:"persisted"`
}

// ExecutePhaseOne is the explicit business entry point, shared by formal reports
// and the read-only validator. persist=false never executes S or writes caches.
func (s Services) ExecutePhaseOne(ctx context.Context, snap EvidenceSnapshot, facts SnapshotFactEvaluation, sem ReportSemanticEvaluation, history ReportHistory, assets []domain.Asset, persist bool) (PhaseOneEvaluation, error) {
	out := PhaseOneEvaluation{}
	cfg := evidence.DefaultPhaseOneConfig()
	options := s.ReportOptions
	if options == nil {
		o, err := config.LoadReportOptions()
		if err != nil {
			return out, err
		}
		options = &o
	}
	if len(options.PhaseOnePoints) > 0 {
		cfg.Points = options.PhaseOnePoints
		if options.PhaseOnePolicyVersion == "" {
			return out, fmt.Errorf("phase_one_policy_version_required_for_custom_points")
		}
	}
	if options.PhaseOnePolicyVersion != "" {
		cfg.Version = options.PhaseOnePolicyVersion
	}
	if options.PhaseOneMaxScore != 0 {
		cfg.MaxScore = options.PhaseOneMaxScore
	}
	if s.PhaseOnePolicy != nil {
		cfg = *s.PhaseOnePolicy
	}
	if err := cfg.Validate(); err != nil {
		return out, err
	}
	materials := PhaseOneMaterials{Complete: false, Diagnostics: []string{"current_wire_materials_unavailable"}}
	if facts.Manifest.PhaseOne != nil {
		materials = *facts.Manifest.PhaseOne
		materials.Complete = materials.Complete && facts.Manifest.Coverage == "complete"
		for i := range materials.Sources {
			if materials.Expanded {
				break
			}
			materials.Sources[i].LoadedHits = facts.Manifest.LoadedHits
			materials.Sources[i].Complete = materials.Complete
		}
	}
	// Reuse the manifest's current-frame bindings; never scan the current hits a
	// second time. History fetches are bounded and independently versioned.
	timelineCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	merged := materials
	var err error
	if !materials.Expanded {
		merged, err = s.phaseOneTimeline(timelineCtx, snap, materials, history, assets)
	}
	merged.Expanded = true
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		merged.Complete = false
		merged.Diagnostics = append(merged.Diagnostics, "timeline_read_failed:"+err.Error())
	}
	out.Materials = merged
	key := digest([]any{evidence.PhaseOneVersion, evidence.RuleVersion, semanticAdapterVersion, cfg, snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark, materials, merged, history, sem.ResultKey, sem.Result, facts.Result})
	out.CacheKey = key
	if persist {
		if record, ok, readErr := s.Store.AggregateRecord(ctx, "phase_one_result", key); readErr == nil && ok {
			var cached PhaseOneEvaluation
			if json.Unmarshal(record.Value, &cached) == nil && cached.Result.Version == evidence.PhaseOneVersion && cached.CacheKey == key {
				expected, validateErr := evidence.EvaluatePhaseOne(snap.EventID, snap.Version, cached.Facts, sem.Result, materials.Bindings, cfg)
				if validateErr == nil && facts.Result != nil && digest(cached.Facts) == digest(facts.Result.Findings) && digest(expected) == digest(cached.Result) {
					cached.CacheHit = true
					return cached, nil
				}
			}
		}
	}
	findings, computeErr := phaseOneCurrentFacts(ctx, snap, materials, history)
	if computeErr != nil {
		return out, computeErr
	}
	// Only independent contacts enter the existing temporal algorithms. Evaluate
	// each IOC separately even when it shares an endpoint with another indicator.
	groups := map[string][]PhaseOneContact{}
	for _, c := range merged.Contacts {
		k := scopeKey(c.Scope) + c.IOCType + ":" + c.IOCValue
		groups[k] = append(groups[k], c)
	}
	for _, contacts := range groups {
		req := evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: []evidence.FactID{"F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW"}, Quality: evidence.Quality{Coverage: evidence.CoverageComplete}}
		complete := merged.Complete
		req.Quality.SavedTimelineComplete = &complete
		truncated := false
		req.Quality.CaptureTruncated = &truncated
		if !complete {
			req.Quality.Coverage = evidence.CoveragePartial
		}
		for _, c := range contacts {
			req.Hits = append(req.Hits, evidence.Hit{ID: c.HitID, OccurredAt: c.Time, Scope: c.Scope})
		}
		fc := evidence.DefaultConfig()
		fc.Policies = map[evidence.FactID]map[string]float64{"F_BEACON_JITTER": {"ljung_box_lags": 3, "median_relative_tolerance": 0.25}}
		engine, _ := evidence.NewEngine(fc)
		computed, e := engine.Evaluate(ctx, req)
		if e != nil {
			return out, e
		}
		for _, f := range computed.Findings {
			f.IOCType, f.IOCValue = contacts[0].IOCType, contacts[0].IOCValue
			findings = append(findings, f)
		}
	}
	// Missing contacts need explicit F outcomes, never inherited packet-count F.
	for _, b := range materials.Bindings {
		if !b.Verified {
			continue
		}
		for _, id := range []evidence.FactID{"F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW"} {
			found := false
			for _, f := range findings {
				if f.Scope == b.Scope && f.FactID == id && f.IOCType == b.IOCType && f.IOCValue == b.IOCValue {
					found = true
				}
			}
			if !found {
				findings = append(findings, evidence.Finding{IOCType: b.IOCType, IOCValue: b.IOCValue, FactID: id, Scope: b.Scope, SnapshotVersion: snap.Version, RuleVersion: evidence.RuleVersion, Status: evidence.Missing, Eligibility: "ineligible", Quality: "partial", ReasonCode: evidence.InsufficientSamples, Limitations: []string{"no independent communication observations; packet count is not contact count"}})
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		return scopeKey(a.Scope)+a.IOCType+a.IOCValue+string(a.FactID)+fmt.Sprint(a.SourceIDs) < scopeKey(b.Scope)+b.IOCType+b.IOCValue+string(b.FactID)+fmt.Sprint(b.SourceIDs)
	})
	out.Facts = findings
	result, e := evidence.EvaluatePhaseOne(snap.EventID, snap.Version, findings, sem.Result, materials.Bindings, cfg)
	if e != nil {
		return out, e
	}
	out.Result = result
	if !persist {
		out.Result.Diagnostics = append(out.Result.Diagnostics, "read_only_no_semantic_execution_no_cache_write")
	}
	if persist {
		out.Persisted = true
		if e := putRecord(ctx, s.Store, "phase_one_result", key, snap.EventID, out); e != nil {
			out.Persisted = false
			out.Result.Diagnostics = append(out.Result.Diagnostics, "phase_one_cache_write_failed")
		}
		if e := putRecord(ctx, s.Store, "phase_one_diagnostics", snapshotKey(snap.EventID, snap.Version), snap.EventID, out); e != nil {
			out.Result.Diagnostics = append(out.Result.Diagnostics, "phase_one_diagnostics_write_failed")
		}
	}
	return out, nil
}

func phaseOneContext(raw string, p PhaseOneEvaluation) (string, error) {
	var c map[string]any
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return "", err
	}
	c["phase_one_evidence"] = map[string]any{"result": p.Result, "cache_key": p.CacheKey, "persisted": p.Persisted, "diagnostics": p.Materials.Diagnostics, "independent_contacts": len(p.Materials.Contacts), "source_snapshots": p.Materials.Sources}
	data, err := json.Marshal(c)
	return string(data), err
}
