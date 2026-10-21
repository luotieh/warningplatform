package service

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const reportHistoryVersion = "platform-history-0.5"

type ReportHistoryDiagnostics struct {
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Candidates int    `json:"candidate_count"`
	Matched    int    `json:"matched_count"`
	Excluded   int    `json:"excluded_count"`
	Truncated  bool   `json:"truncated"`
}
type ReportHistoryRow struct {
	DestinationEndpoint string         `json:"destination_endpoint,omitempty"`
	VerifiedDNSHitIDs   []string       `json:"verified_dns_hit_ids,omitempty"`
	SourceAddress       string         `json:"source_address,omitempty"`
	DestinationAddress  string         `json:"destination_address,omitempty"`
	DeviceID            string         `json:"device_id"`
	Application         map[string]any `json:"application,omitempty"`
	ActivityType        string         `json:"activity_type"`
	EventID             string         `json:"event_id"`
	AssetIDs            []string       `json:"asset_ids"`
	AllAssetIDs         []string       `json:"all_asset_ids"`
	ActivityIOCs        []domain.IOC   `json:"activity_iocs"`
	IOCs                []domain.IOC   `json:"iocs"`
	Relation            string         `json:"relation"`
	First               time.Time      `json:"first_time"`
	Last                time.Time      `json:"last_time"`
	ReviewStatus        string         `json:"review_status"`
	Adjudication        string         `json:"adjudication"`
	AdjudicationID      string         `json:"adjudication_id,omitempty"`
	AdjudicationSource  string         `json:"adjudication_source,omitempty"`
}
type ReportHistory struct {
	RelatedRows                []ReportHistoryRow          `json:"related_rows,omitempty"`
	EventSummaryOnly           bool                        `json:"event_summary_only,omitempty"`
	EventSummaryComplete       bool                        `json:"event_summary_complete,omitempty"`
	FrozenSnapshots            map[string]EvidenceSnapshot `json:"frozen_snapshots,omitempty"`
	SnapshotIssues             map[string]string           `json:"snapshot_issues,omitempty"`
	ExactRelations             bool                        `json:"exact_relations,omitempty"`
	ReadPages                  int                         `json:"read_pages"`
	RawDNSVerificationRequired bool                        `json:"raw_dns_verification_required,omitempty"`
	RawDNSStatus               string                      `json:"raw_dns_status,omitempty"`
	RawDNSReadHits             int                         `json:"raw_dns_read_hits,omitempty"`
	MatchAddresses             []string                    `json:"match_addresses"`
	MatchIOCs                  []domain.IOC                `json:"match_iocs"`
	Version                    string                      `json:"version"`
	Status                     string                      `json:"status"`
	Reason                     string                      `json:"reason,omitempty"`
	Start                      time.Time                   `json:"lookback_start"`
	End                        time.Time                   `json:"as_of"`
	Issue                      *SnapshotInputIssue         `json:"-"`
	CandidateCount             int                         `json:"candidate_count"`
	ExcludedCount              int                         `json:"excluded_count"`
	Truncated                  bool                        `json:"truncated"`
	Rows                       []ReportHistoryRow          `json:"rows"`
}

func historyIOCs(event domain.Event, c map[string]any) []domain.IOC {
	terms := []domain.IOC{}
	for _, key := range []string{"ioc", "ioc_evidence"} {
		if m, ok := c[key].(map[string]any); ok {
			terms = append(terms, domain.IOC{Type: asString(m["ioc_type"]), Value: asString(m["ioc_value"])})
		}
	}
	if q, ok := c["quant_stats"].(map[string]any); ok {
		if rows, ok := q["by_ioc"].([]any); ok {
			for _, row := range rows {
				if m, ok := row.(map[string]any); ok {
					terms = append(terms, domain.IOC{Type: asString(m["ioc_type"]), Value: asString(m["ioc_value"])})
				}
			}
		}
	}
	// Actual parsed DNS fields are typed observations, independent of which IOC
	// rule triggered the hit. Retain query/answer associations, not resolver IPs.
	if app, ok := c["app"].(map[string]any); ok {
		if query := asString(app["dns_query"]); query != "" {
			terms = append(terms, domain.IOC{Type: "domain", Value: query})
		}
		if answers, ok := app["dns_answers"].([]any); ok {
			for _, answer := range answers {
				if value := asString(answer); value != "" {
					terms = append(terms, domain.IOC{Type: "ip", Value: value})
				}
			}
		}
	}
	// Source/destination observables include assets and recursive resolvers.
	// They describe transport, not the IOC that triggered this event. Only use
	// observables as a legacy fallback when no explicit IOC is available.
	if len(terms) == 0 {
		terms = append(terms, event.Observables...)
	}
	unique := map[string]domain.IOC{}
	for _, ioc := range terms {
		ioc.Type = strings.ToLower(strings.TrimSpace(ioc.Type))
		ioc.Value = strings.TrimSpace(ioc.Value)
		if ioc.Type == "domain" {
			ioc.Value = strings.ToLower(strings.TrimSuffix(ioc.Value, "."))
		}
		if ip, err := netip.ParseAddr(ioc.Value); err == nil {
			ioc.Value = ip.Unmap().String()
		}
		if ioc.Type != "" && ioc.Value != "" {
			ioc.Role = ""
			unique[ioc.Type+":"+ioc.Value] = ioc
		}
	}
	keys := []string{}
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []domain.IOC{}
	for _, key := range keys {
		out = append(out, unique[key])
	}
	return out
}

func (s Services) loadReportHistory(ctx context.Context, event domain.Event, snap EvidenceSnapshot, assets []domain.Asset, _ ...*EvidenceSourceRegistry) ReportHistory {
	return s.loadReportHistoryMode(ctx, event, snap, assets, false)
}
func (s Services) loadReportHistoryMode(ctx context.Context, event domain.Event, snap EvidenceSnapshot, assets []domain.Asset, exact bool) ReportHistory {
	h := ReportHistory{Version: reportHistoryVersion, Status: "unavailable", Rows: []ReportHistoryRow{}}
	h.ExactRelations = exact
	first, err := time.Parse(time.RFC3339Nano, asString(snap.Context["first_time"]))
	if err != nil {
		h.Reason = "history_window_unavailable"
		return h
	}
	h.End = first
	h.Start = first.AddDate(0, 0, -30)
	q := store.HistoryQuery{Start: h.Start, End: h.End, ExcludeIDs: append([]string{event.EventID}, snap.Sources...), Limit: 201}
	addresses := map[string]bool{}
	currentAssets := map[string]bool{}
	for _, sample := range snap.Evidence {
		for _, key := range []string{"src_ip", "dst_ip"} {
			address := asString(sample[key])
			if id, ok := registeredSnapshotAsset(assets, address); ok {
				addresses[address] = true
				currentAssets[id] = true
			}
		}
	}
	for address := range addresses {
		q.Addresses = append(q.Addresses, address)
	}
	sort.Strings(q.Addresses)
	for _, ioc := range historyIOCs(event, snap.Context) {
		if _, asset := registeredSnapshotAsset(assets, ioc.Value); !asset {
			q.IOCs = append(q.IOCs, ioc)
		}
	}
	if len(q.Addresses)+len(q.IOCs) == 0 {
		h.Reason = "history_identity_unresolved"
		return h
	}
	h.MatchAddresses = append([]string(nil), q.Addresses...)
	h.MatchIOCs = append([]domain.IOC(nil), q.IOCs...)
	if exact {
		q.DeviceID = asString(snap.Context["device_id"])
		for _, a := range q.Addresses {
			for _, ioc := range q.IOCs {
				q.ExactRelations = append(q.ExactRelations, store.HistoryRelation{Address: a, IOC: ioc})
			}
		}
		if q.DeviceID == "" || len(q.ExactRelations) == 0 {
			h.Reason = "history_exact_identity_unresolved"
			return h
		}
	}
	if len(q.Addresses) > 32 || len(q.IOCs) > 32 || len(q.ExcludeIDs) > 256 {
		h.Reason = "history_identity_budget_exceeded"
		return h
	}
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	candidates, err := s.Store.HistoryCandidates(readCtx, q)
	h.ReadPages++
	if exact && err == nil {
		// Stable keyset pagination; unrelated IOC/asset candidates never consume
		// the phase-one budget. The final sentinel diagnoses partial coverage.
		for len(candidates) > 0 && len(candidates)%201 == 0 && len(candidates) < 5001 {
			tail := candidates[len(candidates)-1]
			q.BeforeTime = tail.CreatedAt
			if tail.LastSeenAt != nil {
				q.BeforeTime = *tail.LastSeenAt
			}
			q.AfterID = tail.EventID
			page, readErr := s.Store.HistoryCandidates(readCtx, q)
			h.ReadPages++
			if readErr != nil {
				err = readErr
				break
			}
			if len(page) == 0 {
				break
			}
			candidates = append(candidates, page...)
			if len(page) < 201 {
				break
			}
		}
	}
	if err != nil {
		h.Reason = "history_query_failed"
		issue := snapshotIssueCause(SnapshotInputIssue{Code: h.Reason, Stage: "load_history", Retryable: true}, err)
		h.Issue = &issue
		return h
	}
	h.CandidateCount = len(candidates)
	maxRows := 200
	if exact {
		maxRows = 5000
	}
	h.Truncated = len(candidates) > maxRows
	if h.Truncated {
		candidates = candidates[:maxRows]
	}
	bytes := 0
	seen := map[string]bool{}
	for _, id := range q.ExcludeIDs {
		seen[id] = true
	}
	for _, e := range candidates {
		bytes += len(e.Context)
		if bytes > 4<<20 {
			h.Truncated = true
			break
		}
		if seen[e.EventID] {
			h.ExcludedCount++
			continue
		}
		c := decodeEventContext(e.Context)
		if canonical := asString(c["canonical_event_id"]); canonical != "" && canonical != e.EventID {
			h.ExcludedCount++
			continue
		}
		seen[e.EventID] = true
		start, err := time.Parse(time.RFC3339Nano, asString(c["first_time"]))
		if err != nil {
			start, err = time.Parse(time.RFC3339Nano, asString(c["occurrence_time"]))
		}
		end, endErr := time.Parse(time.RFC3339Nano, asString(c["last_time"]))
		if endErr != nil && e.LastSeenAt != nil {
			end = *e.LastSeenAt
			endErr = nil
		}
		if endErr != nil && err == nil {
			end = start
			endErr = nil
		}
		// Creation time is not an invented activity timestamp for legacy events.
		if err != nil || endErr != nil || start.After(end) || start.Before(h.Start) || !end.Before(h.End) {
			h.ExcludedCount++
			continue
		}
		matchedAssets := map[string]bool{}
		for _, key := range []string{"src_ip", "dst_ip"} {
			if id, ok := registeredSnapshotAsset(assets, asString(c[key])); ok && currentAssets[id] {
				matchedAssets[id] = true
			}
		}
		row := ReportHistoryRow{EventID: e.EventID, First: start, Last: end, AssetIDs: []string{}, IOCs: []domain.IOC{}, ReviewStatus: e.ReviewStatus, Adjudication: "unreviewed"}
		row.ActivityType = e.Category
		row.DeviceID = asString(c["device_id"])
		if exact && row.DeviceID != q.DeviceID {
			h.ExcludedCount++
			continue
		}
		row.Application = nestedMap(c, "app")
		row.SourceAddress, row.DestinationAddress = asString(c["src_ip"]), asString(c["dst_ip"])
		row.ActivityIOCs = historyIOCs(e, c)
		for _, key := range []string{"src_ip", "dst_ip"} {
			if id, ok := registeredSnapshotAsset(assets, asString(c[key])); ok && !slices.Contains(row.AllAssetIDs, id) {
				row.AllAssetIDs = append(row.AllAssetIDs, id)
			}
		}
		for id := range matchedAssets {
			row.AssetIDs = append(row.AssetIDs, id)
		}
		sort.Strings(row.AssetIDs)
		for _, ioc := range historyIOCs(e, c) {
			for _, target := range q.IOCs {
				if ioc.Type == target.Type && ioc.Value == target.Value {
					row.IOCs = append(row.IOCs, ioc)
					break
				}
			}
		}
		switch {
		case len(row.AssetIDs) > 0 && len(row.IOCs) > 0:
			row.Relation = "same_asset_ioc"
		case len(row.IOCs) > 0:
			row.Relation = "same_ioc"
		case len(row.AssetIDs) > 0:
			row.Relation = "same_asset"
		default:
			h.ExcludedCount++
			continue
		}
		h.Rows = append(h.Rows, row)
	}
	h.Status = "available"
	if h.Truncated {
		h.Status = "partial"
		h.Reason = "history_candidate_budget_exceeded"
	}
	if len(h.Rows) == 0 && !h.Truncated {
		h.Reason = "no_matching_platform_history"
	}
	if !exact {
		s.verifyReportHistoricalDNS(ctx, snap, &h)
	}
	// Ordinary approval/rejection is a workflow state, not an independently
	// verified malicious/false-positive adjudication; do not synthesize one.
	return h
}

// One adapter converts the shared retrieval to engine inputs. Algorithms remain
// storage independent; review workflow state never filters these records.
func applyPlatformHistory(out *SnapshotEvidenceInput, snap EvidenceSnapshot, history *ReportHistory) {
	if history == nil || history.Status == "unavailable" {
		return
	}
	for n := range out.Request.Inputs {
		i := &out.Request.Inputs[n]
		if i.Window == nil || i.Window.Start.IsZero() {
			continue
		}
		p := evidence.Provenance{Verified: true, Complete: !history.Truncated && history.ExcludedCount == 0, Version: history.Version + ":" + digest(history), SourceIDs: []string{snapshotKey(snap.EventID, snap.Version)}}
		h := &evidence.HistoryData{Provenance: p, PlatformRecords: true, AsOf: history.End, LookbackStart: history.Start, Endpoint: i.Scope.EndpointID}
		// Prefer the actual queried domain over its recursive resolver endpoint.
		for _, target := range history.MatchIOCs {
			if target.Type == "domain" && i.DNS != nil {
				for _, row := range i.DNS.Records {
					if strings.EqualFold(strings.TrimSuffix(row.Domain, "."), strings.TrimSuffix(target.Value, ".")) {
						h.IOC = target.Value
					}
				}
			}
		}
		// Bind only an IOC at this endpoint; never copy another scope's IOC.
		endpoint := strings.TrimPrefix(strings.TrimPrefix(i.Scope.EndpointID, "tcp://"), "udp://")
		host, _, _ := net.SplitHostPort(endpoint)
		for _, target := range history.MatchIOCs {
			if h.IOC == "" && target.Type == "ip" && target.Value == host {
				h.IOC = target.Value
			}
		}
		if h.IOC == "" {
			for _, target := range history.MatchIOCs {
				if i.DNS != nil {
					for _, row := range i.DNS.Records {
						if row.Domain == target.Value {
							h.IOC = target.Value
						}
					}
				}
			}
		}
		for _, row := range history.Rows {
			if !row.Last.Before(i.Window.Start) {
				h.Complete = false
				continue
			}
			// One engine row per event prevents inflated recurrence counts. A
			// multi-asset record has no unique owner and remains semantic context.
			asset := ""
			if len(row.AllAssetIDs) == 1 {
				asset = row.AllAssetIDs[0]
			}
			ioc := ""
			for _, candidate := range row.ActivityIOCs {
				if candidate.Value == h.IOC {
					ioc = h.IOC
					break
				}
			}
			if ioc == "" && len(row.ActivityIOCs) == 1 {
				ioc = row.ActivityIOCs[0].Value
			}
			kind := "ioc_record"
			if asString(row.Application["dns_query"]) != "" {
				kind = "dns_record"
			} else if row.SourceAddress == ioc || row.DestinationAddress == ioc {
				kind = "transport_contact"
			}
			h.Events = append(h.Events, evidence.HistoryEvent{ID: row.EventID, DeviceID: row.DeviceID, AssetID: asset, AssetIDs: row.AllAssetIDs, IOC: ioc, Time: row.First, Relation: row.Relation, ActivityType: row.ActivityType, ObservationKind: kind})
			h.SourceIDs = append(h.SourceIDs, row.EventID)
		}
		i.PlatformHistory = h
		if i.History == nil {
			i.History = h
		}
	}
}
