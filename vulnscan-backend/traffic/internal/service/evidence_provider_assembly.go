package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func assembleProviderTraffic(snap EvidenceSnapshot, assets []domain.Asset, hits []store.Hit, w evidence.AnalysisWindow) (SnapshotEvidenceInput, []string, map[string]bool, error) {
	out := SnapshotEvidenceInput{Request: evidence.Request{EventID: snap.EventID, SnapshotVersion: snap.Version, Facts: evidence.SupportedFacts(), Hits: []evidence.Hit{}, Inputs: []evidence.Input{}, Groups: []evidence.GroupInput{}, Quality: evidence.Quality{Coverage: evidence.CoveragePartial}}, Manifest: SnapshotEvidenceManifest{AdapterVersion: reportSnapshotAdapterVersion, SnapshotVersion: snap.Version, Watermark: snap.Watermark, RevisionWatermark: snap.RevisionWatermark, DeclaredHits: snap.Count, LoadedHits: int64(len(hits)), Coverage: "partial", PhaseOne: &PhaseOneMaterials{Expanded: true, Complete: false, CurrentComplete: false, Sources: []PhaseOneSnapshotSource{}, Records: []PhaseOneRecord{}, Bindings: []evidence.PhaseOneBinding{}, Diagnostics: []string{}}}}
	bound := map[evidence.Scope]*evidence.Input{}
	addresses := []string{}
	devices := map[string]bool{}
	sessions := newProviderSessionAccumulator(assets)
	source := phaseOneSnapshotSource(snap)
	source.LoadedHits = int64(len(hits))
	source.Complete = int64(len(hits)) == snap.Count
	out.Manifest.PhaseOne.Sources = append(out.Manifest.PhaseOne.Sources, source)
	for _, h := range hits {
		out.Manifest.JSONDecodeCount++
		out.Manifest.RawBytes += int64(len(h.Raw))
		m := map[string]any{}
		d := json.NewDecoder(strings.NewReader(string(h.Raw)))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			return out, nil, nil, fmt.Errorf("saved_hit_json_invalid:%s", h.ID)
		}
		scope, remote, port, ok := snapshotScope(m, assets)
		if !ok {
			out.Manifest.UnresolvedHits++
			out.Manifest.addIssue(SnapshotInputIssue{Code: "asset_device_endpoint_binding_unresolved", Stage: "provider_bind", HitID: h.ID})
			continue
		}
		out.Manifest.BoundHits++
		devices[scope.DeviceID] = true
		for _, key := range []string{"src_ip", "dst_ip"} {
			address := asString(m[key])
			if id, ok := registeredSnapshotAsset(assets, address); ok && id == scope.AssetID {
				addresses = append(addresses, address)
			}
		}
		eh := evidence.Hit{ID: h.ID, OccurredAt: h.OccurredAt, Scope: scope} // saved hit counters are not independent packet counts
		out.Request.Hits = append(out.Request.Hits, eh)
		in := bound[scope]
		if in == nil {
			in = &evidence.Input{Scope: scope, Window: &evidence.AnalysisWindow{Start: w.Start, End: w.End}}
			bound[scope] = in
		}
		// Keep summary-only sources usable, but never interpret their timestamps
		// as independent communications. Wire sources take the validated parser.
		appView := make(map[string]any, len(m))
		for key, value := range m {
			if key != "raw_packet" {
				appView[key] = value
			}
		}
		adaptSnapshotProtocols(in, h, appView, remote, port, false)
		wire := asString(nestedMap(m, "raw_packet")["packet_hex"]) != ""
		wireVerified, wireRecord := false, false
		if wire || len(nestedMap(m, "exchange")) > 0 {
			normalizeProviderIOC(m)
			parsed := &snapshotParseContext{}
			m[snapshotParseContextKey] = parsed
			exchange := providerVerifiedHTTP(m)
			exchangeVerified := exchange != nil && exchange.Request != nil && providerExchangeInWindow(exchange, in)
			if exchange != nil {
				out.Manifest.WireFrameDecodeCount += int64(exchange.FrameDecodes)
				out.Manifest.HTTPRequestParseCount += int64(exchange.FramingParses)
			}
			reportVerifyDatagram(m)
			_, why := snapshotFramePayload(nestedMap(m, "raw_packet"), m, in)
			wireVerified = why == ""
			if wireVerified || exchangeVerified {
				enrichSnapshotProtocols(in, h, m, &out.Manifest)
			} else {
				out.Manifest.addIssue(SnapshotInputIssue{Code: why, Stage: "parse_protocol", HitID: h.ID, Scope: scope})
			}
			before := len(out.Manifest.PhaseOne.Records)
			collectPhaseOneMaterials(&out.Manifest, h, m, *in, assets, snap)
			appendProviderExchangeContact(&out.Manifest, h, m, *in, assets, snap)
			wireRecord = len(out.Manifest.PhaseOne.Records) > before
			if wireVerified || exchangeVerified {
				collectSnapshotSemanticObservation(&out, in, h, m, assets)
			}
			out.Manifest.ReportObservations = append(out.Manifest.ReportObservations, reportMaterialObservation(h, m, scope))
			sessions.observe(h, m, *in)
			out.Manifest.WireFrameDecodeCount += parsed.frameDecodes
			out.Manifest.HTTPRequestParseCount += parsed.httpParses
			out.Manifest.DNSMessageParseCount += parsed.dnsParses
		} else {
			sessions.observe(h, m, *in)
		}
		last := &in.Network.Connections[len(in.Network.Connections)-1]
		last.Transport = strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])))
		app := nestedMap(m, "app")
		if p := asString(app["app_protocol"]); p != "" && !wireVerified {
			last.AppProtocol = p
			last.ProtocolParsed = true
		}
		if sni := asString(app["tls_sni"]); sni != "" && !wireVerified {
			if in.TLS == nil {
				in.TLS = &evidence.TLSData{}
			}
			in.TLS.Records = append(in.TLS.Records, evidence.TLSRecord{SourceID: h.ID, Time: h.OccurredAt, SNI: sni})
		}
		rec := PhaseOneRecord{Hit: eh}
		if in.HTTP != nil && len(in.HTTP.Records) > 0 && in.HTTP.Records[len(in.HTTP.Records)-1].SourceID == h.ID {
			x := in.HTTP.Records[len(in.HTTP.Records)-1]
			rec.HTTP = &x
			rec.HTTPCandidate = true
		}
		if in.DNS != nil && len(in.DNS.Records) > 0 && in.DNS.Records[len(in.DNS.Records)-1].SourceID == h.ID {
			x := in.DNS.Records[len(in.DNS.Records)-1]
			rec.DNS = &x
		}
		ioc, field := providerStoredIOCField(m, remote)
		rec.IOCType, rec.IOCValue = ioc.Type, ioc.Value
		// An association to a saved field does not establish an independent contact.
		binding := evidence.PhaseOneBinding{Scope: scope, IOCType: ioc.Type, IOCValue: ioc.Value, SourceID: h.ID, Verified: true, Field: field}
		if binding.Field != "" && !wireVerified {
			out.Manifest.PhaseOne.Bindings = append(out.Manifest.PhaseOne.Bindings, binding)
		}
		if !wireRecord {
			out.Manifest.PhaseOne.Records = append(out.Manifest.PhaseOne.Records, rec)
			markPhaseOneScopeIncomplete(out.Manifest.PhaseOne, scope, ioc.Type, ioc.Value, "ioc_wire_frame_missing")
		}
	}
	for scope, in := range bound {
		refs := []string{}
		for _, h := range out.Request.Hits {
			if h.Scope == scope {
				refs = append(refs, h.ID)
			}
		}
		p := evidence.Provenance{Verified: true, Complete: false, Version: fmt.Sprintf("saved-fields:%s:%d:%d:%d", snap.EventID, snap.Version, snap.Watermark, snap.RevisionWatermark), SourceIDs: refs}
		if in.Network != nil {
			in.Network.Provenance = p
		}
		if in.DNS != nil {
			in.DNS.Provenance = p
		}
		if in.HTTP != nil {
			in.HTTP.Provenance = p
			in.HTTP.RequestCandidates = len(in.HTTP.Records) + len(in.HTTP.UnknownRequestIDs)
		}
		if in.TLS != nil {
			in.TLS.Provenance = p
		}
		out.Request.Inputs = append(out.Request.Inputs, *in)
	}
	sort.Slice(out.Request.Inputs, func(i, j int) bool {
		return scopeKey(out.Request.Inputs[i].Scope) < scopeKey(out.Request.Inputs[j].Scope)
	})
	sessions.apply(&out)
	materials := dedupPhaseOneContacts(*out.Manifest.PhaseOne)
	materials.CurrentContacts = append([]PhaseOneContact(nil), materials.Contacts...)
	materials.CurrentIncomplete = clonePhaseOneIncomplete(materials.ScopeIncomplete)
	materials.Diagnostics = append(materials.Diagnostics, "independent contacts require validated wire identity; full communication-window coverage is not inferred from snapshot membership")
	out.Manifest.PhaseOne = &materials
	return out, uniqueSortedStrings(addresses), devices, nil
}

func normalizeProviderIOC(m map[string]any) {
	// Platform ingestion saves IOC under ioc; the shared wire parser consumes
	// the legacy flat shape. Never replace an explicitly conflicting value.
	ioc := nestedMap(m, "ioc")
	for _, key := range []string{"ioc_type", "ioc_value"} {
		if asString(m[key]) == "" {
			m[key] = ioc[key]
		}
	}
}

func assembleProviderHistory(h ReportHistory, rows []domain.Event, assets []domain.Asset, devices map[string]bool, truncated bool) ReportHistory {
	h.Status = "available"
	h.CandidateCount = len(rows)
	h.EventSummaryOnly, h.EventSummaryComplete = true, !truncated
	h.Truncated = true // alert history never proves full communication coverage
	if truncated {
		h.Reason = "candidate_budget_exceeded"
	} else {
		h.Reason = "saved_event_history_partial_network_visibility"
	}
	for _, e := range rows {
		c := decodeEventContext(e.Context)
		device := asString(c["device_id"])
		if !devices[device] {
			h.ExcludedCount++
			continue
		}
		first, e1 := time.Parse(time.RFC3339Nano, asString(c["first_time"]))
		last, e2 := time.Parse(time.RFC3339Nano, asString(c["last_time"]))
		if e1 != nil || e2 != nil || last.Before(first) || first.Before(h.Start) || !last.Before(h.End) {
			h.EventSummaryComplete = false
			h.ExcludedCount++
			continue
		}
		ids := []string{}
		for _, key := range []string{"src_ip", "dst_ip"} {
			if id, ok := registeredSnapshotAsset(assets, asString(c[key])); ok {
				ids = append(ids, id)
			}
		}
		ids = uniqueSortedStrings(ids)
		if len(ids) != 1 {
			h.ExcludedCount++
			continue
		}
		matched := []domain.IOC{}
		for _, ioc := range h.MatchIOCs {
			for _, address := range h.MatchAddresses {
				if providerHistoryRelation(c, store.HistoryRelation{Address: address, IOC: ioc}) {
					matched = append(matched, ioc)
				}
			}
		}
		if len(matched) == 0 {
			h.ExcludedCount++
			continue
		}
		h.Rows = append(h.Rows, ReportHistoryRow{DestinationEndpoint: providerSavedHistoryEndpoint(c, assets, ids), EventID: e.EventID, DeviceID: device, First: first, Last: last, AssetIDs: ids, AllAssetIDs: ids, IOCs: matched, ActivityIOCs: matched, Application: nestedMap(c, "app"), SourceAddress: asString(c["src_ip"]), DestinationAddress: asString(c["dst_ip"]), Relation: "same_asset_ioc", ActivityType: e.Category, Adjudication: "unreviewed"})
	}
	return h
}

func appendCollectedProviderPeers(ctx context.Context, out *SnapshotEvidenceInput, assets []domain.Asset, peers []CollectedTrafficSnapshot, w evidence.AnalysisWindow, a *EvidenceSupplyAudit) error {
	// Related events may add saved, independently owned observations. A shared
	// IOC alone cannot supply business membership, synchronized contacts or
	// complete campaign coverage; groups remain candidates with Complete=false.
	members := map[evidence.Scope][]string{}
	for _, h := range out.Request.Hits {
		members[h.Scope] = append(members[h.Scope], h.ID)
	}
	seen := map[string]bool{}
	for _, h := range out.Request.Hits {
		seen[h.ID] = true
	}
	for _, peer := range peers {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, hits := peer.Snapshot, collectedStoreHits(peer.Hits)
		input, _, _, err := assembleProviderTraffic(s, assets, hits, w)
		if err != nil {
			return err
		}
		out.Manifest.BoundHits += input.Manifest.BoundHits
		out.Manifest.UnresolvedHits += input.Manifest.UnresolvedHits
		out.Manifest.LoadedHits += input.Manifest.LoadedHits
		out.Manifest.DeclaredHits += input.Manifest.DeclaredHits
		out.Manifest.RawBytes += input.Manifest.RawBytes
		out.Manifest.JSONDecodeCount += input.Manifest.JSONDecodeCount
		out.Manifest.WireFrameDecodeCount += input.Manifest.WireFrameDecodeCount
		out.Manifest.HTTPRequestParseCount += input.Manifest.HTTPRequestParseCount
		out.Manifest.DNSMessageParseCount += input.Manifest.DNSMessageParseCount
		out.Manifest.PhaseOne.Records = append(out.Manifest.PhaseOne.Records, input.Manifest.PhaseOne.Records...)
		out.Manifest.PhaseOne.Bindings = append(out.Manifest.PhaseOne.Bindings, input.Manifest.PhaseOne.Bindings...)
		out.Manifest.PhaseOne.Contacts = append(out.Manifest.PhaseOne.Contacts, input.Manifest.PhaseOne.Contacts...)
		for key, reasons := range input.Manifest.PhaseOne.ScopeIncomplete {
			if out.Manifest.PhaseOne.ScopeIncomplete == nil {
				out.Manifest.PhaseOne.ScopeIncomplete = map[string][]string{}
			}
			out.Manifest.PhaseOne.ScopeIncomplete[key] = append(out.Manifest.PhaseOne.ScopeIncomplete[key], reasons...)
		}

		out.SemanticObservations = append(out.SemanticObservations, input.SemanticObservations...)
		out.Manifest.ReportObservations = append(out.Manifest.ReportObservations, input.Manifest.ReportObservations...)
		out.Manifest.Issues = append(out.Manifest.Issues, input.Manifest.Issues...)
		for _, h := range input.Request.Hits {
			if seen[h.ID] {
				return fmt.Errorf("peer_source_ownership_overlap")
			}
			seen[h.ID] = true
			members[h.Scope] = append(members[h.Scope], h.ID)
			out.Request.Hits = append(out.Request.Hits, h)
		}
		for _, in := range input.Request.Inputs {
			matched := false
			for i := range out.Request.Inputs {
				old := &out.Request.Inputs[i]
				if old.Scope != in.Scope {
					continue
				}
				matched = true
				if old.Network != nil && in.Network != nil {
					old.Network.Connections = append(old.Network.Connections, in.Network.Connections...)
					old.Network.SourceIDs = uniqueSortedStrings(append(old.Network.SourceIDs, in.Network.SourceIDs...))
					for _, session := range in.Network.Sessions {
						copy := session
						copy.HitIDs = append([]string(nil), session.HitIDs...)
						old.Network.Sessions = append(old.Network.Sessions, copy)
					}
				} else if in.Network != nil {
					old.Network = in.Network
				}
				if old.HTTP != nil && in.HTTP != nil {
					old.HTTP.Records = append(old.HTTP.Records, in.HTTP.Records...)
					old.HTTP.RequestCandidates += in.HTTP.RequestCandidates
					old.HTTP.SourceIDs = uniqueSortedStrings(append(old.HTTP.SourceIDs, in.HTTP.SourceIDs...))
				} else if in.HTTP != nil {
					old.HTTP = in.HTTP
				}
				if old.DNS != nil && in.DNS != nil {
					old.DNS.Records = append(old.DNS.Records, in.DNS.Records...)
					old.DNS.SourceIDs = uniqueSortedStrings(append(old.DNS.SourceIDs, in.DNS.SourceIDs...))
				} else if in.DNS != nil {
					old.DNS = in.DNS
				}
				if old.TLS != nil && in.TLS != nil {
					old.TLS.Records = append(old.TLS.Records, in.TLS.Records...)
					old.TLS.SourceIDs = uniqueSortedStrings(append(old.TLS.SourceIDs, in.TLS.SourceIDs...))
				} else if in.TLS != nil {
					old.TLS = in.TLS
				}
			}
			if !matched {
				out.Request.Inputs = append(out.Request.Inputs, in)
			}
		}
		source := phaseOneSnapshotSource(s)
		source.LoadedHits = int64(len(hits))
		source.Complete = int64(len(hits)) == s.Count
		out.Manifest.PhaseOne.Sources = append(out.Manifest.PhaseOne.Sources, source)
	}
	endpoints := map[string][]evidence.Scope{}
	for scope := range members {
		endpoints[scope.EndpointID] = append(endpoints[scope.EndpointID], scope)
	}
	keys := []string{}
	for k := range endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, endpoint := range keys {
		scopes := endpoints[endpoint]
		sort.Slice(scopes, func(i, j int) bool { return scopeKey(scopes[i]) < scopeKey(scopes[j]) })
		assetsSeen := map[string]bool{}
		g := evidence.GroupInput{ID: "candidate:" + digest(endpoint), Window: w, Endpoint: endpoint, DNSOwnership: map[string]string{}, Provenance: evidence.Provenance{Verified: true, Complete: false, Version: "provider-candidate-group-2", SourceIDs: []string{}}}
		memberSources := map[string]evidence.Scope{}
		ambiguousAssets := map[string]bool{}
		assetDevices := map[string]string{}
		for _, scope := range scopes {
			if previous, ok := assetDevices[scope.AssetID]; ok && previous != scope.DeviceID {
				ambiguousAssets[scope.AssetID] = true
			}
			assetDevices[scope.AssetID] = scope.DeviceID
		}
		for _, scope := range scopes {
			if ambiguousAssets[scope.AssetID] {
				a.Diagnostics = append(a.Diagnostics, "group_member_multiple_devices:"+scope.AssetID)
				continue
			}
			if assetsSeen[scope.AssetID] {
				continue
			}
			assetsSeen[scope.AssetID] = true
			ids := members[scope]
			g.Members = append(g.Members, evidence.GroupMember{AssetID: scope.AssetID, Scope: scope, HitIDs: ids, MembershipVerified: true})
			g.SourceIDs = append(g.SourceIDs, ids...)
			for _, id := range ids {
				memberSources[id] = scope
			}
		}
		// A saved hit proves this observed endpoint/owner, not an independent
		// initiation or complete campaign. Never copy DNS across endpoints.
		if err := populateProviderGroup(&g, out.Request, memberSources); err != nil {
			return err
		}
		g.SourceIDs = uniqueSortedStrings(g.SourceIDs)
		// Copy an IOC only when every member observation explicitly binds the
		// same IOC. A shared destination or resolver alone cannot supply it.
		commonIOC := ""
		allBound := len(g.SourceIDs) > 0
		for _, id := range g.SourceIDs {
			value := ""
			for _, binding := range out.Manifest.PhaseOne.Bindings {
				if binding.SourceID == id && binding.Verified {
					value = binding.IOCValue
					break
				}
			}
			if value == "" || commonIOC != "" && commonIOC != value {
				allBound = false
			}
			if commonIOC == "" {
				commonIOC = value
			}
		}
		if allBound {
			g.IOC = commonIOC
		}
		if len(g.Members) > 1 {
			out.Request.Groups = append(out.Request.Groups, g)
		}
	}
	sort.Slice(out.Request.Inputs, func(i, j int) bool {
		return scopeKey(out.Request.Inputs[i].Scope) < scopeKey(out.Request.Inputs[j].Scope)
	})
	return nil
}

func applyProviderHistory(out *SnapshotEvidenceInput, snap EvidenceSnapshot, h ReportHistory) {
	for i := range out.Request.Inputs {
		in := out.Request.Inputs[i]
		local := h
		local.Rows = nil
		boundIOCs := []domain.IOC{}
		if out.Manifest.PhaseOne != nil {
			for _, binding := range out.Manifest.PhaseOne.CurrentBindings {
				if binding.Verified && binding.Scope == in.Scope {
					boundIOCs = append(boundIOCs, domain.IOC{Type: binding.IOCType, Value: binding.IOCValue})
				}
			}
		}
		for _, row := range h.Rows {
			if row.DeviceID == in.Scope.DeviceID && len(row.AllAssetIDs) == 1 && row.AllAssetIDs[0] == in.Scope.AssetID {
				local.Rows = append(local.Rows, row)
			}
		}
		for _, row := range h.RelatedRows {
			if providerRelatedHistoryForScope(row, in.Scope, boundIOCs) {
				local.Rows = append(local.Rows, row)
			}
		}
		tmp := SnapshotEvidenceInput{Request: evidence.Request{Inputs: []evidence.Input{in}}}
		applyPlatformHistory(&tmp, snap, &local)
		out.Request.Inputs[i] = tmp.Request.Inputs[0]
	}
}
