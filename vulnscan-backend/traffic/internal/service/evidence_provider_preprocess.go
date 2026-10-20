package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// PreprocessCollectedEvidence is offline and has no Reader, Store or API client.
// It does not mutate the collection and can replay it without a database.
func PreprocessCollectedEvidence(ctx context.Context, collected EvidenceCollection) (b PreparedEvidenceBundle, a EvidenceSupplyAudit, err error) {
	started := time.Now()
	a = collected.Audit
	defer func() {
		a.ElapsedMS += time.Since(started).Milliseconds()
		if err != nil {
			a.Valid = false
		}
	}()
	if err = ctx.Err(); err != nil {
		return b, a, err
	}
	if err = collected.Validate(); err != nil {
		return b, a, err
	}
	c, err := cloneEvidenceCollection(collected)
	if err != nil {
		return b, a, err
	}
	a = c.Audit
	o, snap, event, assets, w := c.Options, c.Snapshot, c.Event, c.Assets, c.Window
	input, _, devices, err := assembleProviderTraffic(snap, assets, collectedStoreHits(c.Hits), w)
	if err != nil {
		return b, a, err
	}
	input.Manifest.MaxHits, input.Manifest.MaxRawBytes = int64(o.MaxHits), o.MaxBytes
	hw := evidence.AnalysisWindow{Start: w.Start.Add(-o.Lookback), End: w.Start}
	history := ReportHistory{Version: "provider-platform-history-1", Start: hw.Start, End: hw.End, MatchAddresses: c.MatchAddresses, MatchIOCs: c.MatchIOCs, Status: "unavailable", Rows: []ReportHistoryRow{}, Truncated: true}
	if len(c.MatchAddresses)+len(c.MatchIOCs) > 0 {
		history = assembleProviderHistory(history, c.HistoryCandidates, assets, devices, c.HistoryTruncated)
		a.HistoryChecks, err = providerHistoryChecks(history, c.HistoryCandidates, assets, devices, c.HistorySnapshots)
		if err != nil {
			return b, a, err
		}
	}
	if err = preprocessProviderTimeline(ctx, c, &input, &history, &a); err != nil {
		return b, a, err
	}
	applyProviderHistory(&input, snap, history)
	if len(c.MatchIOCs) > 0 {
		if err = appendCollectedProviderPeers(ctx, &input, assets, c.Peers, w, &a); err != nil {
			return b, a, err
		}
	}
	dedupProviderContactSets(&input)
	applyProviderTemporalWindowDefault(c, &input)
	buildProviderAssetInputs(&input.Request)
	qi := -1
	for i := range a.Queries {
		if a.Queries[i].ID == "Q:context" {
			qi = i
			break
		}
	}
	if qi < 0 {
		return b, a, fmt.Errorf("collected_context_query_missing")
	}
	registry, reason, err := preprocessProviderSources(c.SourceRegistry)
	if err != nil {
		a.Queries[qi].Status = "failed"
		a.Queries[qi].Reason = reason
		return b, a, err
	}
	if registry != nil {
		a.Queries[qi].Rows = len(registry.Entries)
		produceSnapshotSupplemental(&input, snap, registry)
	} else {
		a.Queries[qi].Reason = reason
		a.Diagnostics = append(a.Diagnostics, reason)
	}
	extra, extraReason, extraErr := preprocessProviderSupplemental(c.Supplemental, snap)
	if extraErr != nil {
		a.Queries[qi].Status = "failed"
		a.Queries[qi].Reason = extraReason
		return b, a, extraErr
	}
	if extra != nil {
		applySnapshotSupplemental(&input, snap, extra)
		a.Queries[qi].Rows += len(extra.Inputs) + len(extra.Groups)
	} else {
		a.Diagnostics = append(a.Diagnostics, extraReason)
	}
	// Construct semantic materials using the existing typed-material assembler;
	// no facts are persisted in the inputs. Actual facts are bound at execution.
	sem := buildSnapshotSemanticRequest(snap, input, &evidence.Result{}, evidence.SemanticRedacted)
	// Observed report summaries may propose group subjects; only the groups
	// actually declared by this provider have a validated membership contract.
	declaredGroups := map[string]bool{}
	for _, group := range input.Request.Groups {
		declaredGroups[group.ID] = true
	}
	subjects := sem.Subjects[:0]
	for _, subject := range sem.Subjects {
		if subject.Scope.GroupID == "" || declaredGroups[subject.Scope.GroupID] {
			subjects = append(subjects, subject)
		}
	}
	sem.Subjects = subjects
	for i := range sem.Subjects {
		sem.Subjects[i].Facts = nil
	}
	input.PreparedSemantics = &sem
	input.Manifest.MissingInputs = snapshotMissingFamilies(input.Request)
	b = PreparedEvidenceBundle{SchemaVersion: PreparedEvidenceSchemaVersion, PreprocessVersion: evidencePreprocessVersion, Event: event, Snapshot: snap, Assets: assets, Inputs: capturePreparedInputs(input), History: history, FactConfig: evidence.DefaultConfig(), SemanticOptions: DefaultReportSemanticOptions(), JointConfig: evidence.DefaultPhaseOneConfig()}
	if o.Profile != nil {
		b.FactConfig = o.Profile.FactConfig
		b.SemanticOptions = o.Profile.SemanticOptions
		b.JointConfig = o.Profile.JointConfig
	}
	b.Coverage = PreparedInputCoverage(b.Inputs)
	b.Seal()
	err = b.Validate()
	a.Valid = err == nil
	if err == nil {
		a.Fields = providerFieldAudit(b, o.Contracts)
		providerAssemblyAudit(b, &a)
	}
	for _, issue := range input.Manifest.Issues {
		a.Diagnostics = append(a.Diagnostics, issue.Stage+":"+issue.Code+":"+scopeKey(issue.Scope))
	}
	a.Diagnostics = append(a.Diagnostics, "Saved wire frames are parsed offline into deduplicated independent contacts and protocol observations; snapshot membership and individual datagram completeness do not prove whole-window communication coverage.", "JSON IOC/address predicates use the existing time index; no asset/IOC JSON index is declared. Query timeout and row/byte budgets apply; no schema migration.")
	if err == nil {
		err = ctx.Err()
	}
	return b, a, err
}

func preprocessProviderSources(r *store.AggregateRecord) (*EvidenceSourceRegistry, string, error) {
	ok := r != nil
	if !ok {
		return nil, "source_registry_not_configured", nil
	}
	v, err := decodeEvidenceSources(r.Value)
	if err != nil {
		return nil, "source_registry_rejected", err
	}
	return v, "", nil
}

func preprocessProviderSupplemental(r *store.AggregateRecord, s EvidenceSnapshot) (*SnapshotSupplementalInputs, string, error) {
	ok := r != nil
	var err error
	if !ok {
		return nil, "supplemental_not_configured", nil
	}
	if len(r.Value) > maxSupplementalBytes {
		return nil, "supplemental_budget_exceeded", fmt.Errorf("supplemental_budget_exceeded")
	}
	var extra SnapshotSupplementalInputs
	d := json.NewDecoder(bytes.NewReader(r.Value))
	d.DisallowUnknownFields()
	if err = d.Decode(&extra); err != nil {
		return nil, "supplemental_record_invalid", err
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil, "supplemental_trailing_data", fmt.Errorf("supplemental_trailing_data")
	}
	if err = validateSnapshotSupplemental(s, extra); err != nil {
		return nil, "supplemental_record_rejected", err
	}
	return &extra, "", nil
}
