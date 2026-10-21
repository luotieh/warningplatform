package evidence

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

func hasTCPSYNAttemptVerification(n *NetworkData) bool {
	for _, row := range n.Connections {
		if row.SYNAttemptVerification != nil {
			return true
		}
	}
	return false
}

type portAttemptGroup struct {
	rows []Connection
	refs []string
	seen map[string]bool
}

// verifiedTCPPortSequence deliberately evaluates only verified saved SYNs. A
// missing or negative subset result cannot refute scanning outside that subset.
// Other network facts still require their existing complete-family contracts.
func (e *Engine) verifiedTCPPortSequence(f Finding, g *observations) Finding {
	n := g.input.Network
	f.SourceIDs = nil
	f.ObservationKind = "verified_tcp_syn_attempt_subset"
	f.Quality = "verified_attempt_subset"
	f.Measurements.SampleCount = 0
	f.FeatureClaim = "Port-order structure among deduplicated verified initial TCP SYN attempts, grouped by source asset/device/address and destination"
	f.CannotProve = "Does not prove a complete network window, completed connections, scan intent, or absence of scanning outside the listed attempts"
	f.Limitations = append(f.Limitations, "Only listed verified initial SYN attempts are measured; missing traffic and connection outcomes are unknown. Each source-address/destination group needs at least eight distinct destination ports; targets are never mixed.")
	if !provenance(n.Provenance) || g.input.Window == nil || !g.input.Window.Start.Before(g.input.Window.End) {
		return absent(f, UnverifiedCoverage)
	}
	sources := map[string]bool{}
	for _, id := range n.SourceIDs {
		sources[id] = true
	}
	hits := map[string]Hit{}
	for _, hit := range g.hits {
		hits[hit.ID] = hit
	}
	validRows := []Connection{}
	poisoned := map[string]bool{}
	identities := map[string]string{}
	skipped, duplicates := 0, 0
	for _, row := range n.Connections {
		v := row.SYNAttemptVerification
		if v == nil {
			skipped++
			continue
		}
		hit, bound := hits[row.SourceID]
		src, srcErr := netip.ParseAddr(v.SourceAddress)
		dst, dstErr := netip.ParseAddr(v.Destination)
		scopeOK := v.Scope.AssetID == g.scope.AssetID && v.Scope.DeviceID == g.scope.DeviceID && v.Scope.GroupID == "" &&
			(g.scope.EndpointID == "asset://"+g.scope.AssetID || v.Scope.EndpointID == g.scope.EndpointID)
		valid := v.Version == TCPSYNAttemptVerificationVersion && row.SourceID != "" && row.SourceID == v.SourceID && sources[row.SourceID] && bound &&
			scopeOK && v.Scope.EndpointID == "tcp://"+net.JoinHostPort(dst.Unmap().String(), stringPort(row.Port)) && hit.Scope == v.Scope && row.AssetID == g.scope.AssetID && hit.OccurredAt.Equal(v.SourceOccurredAt) &&
			!row.Time.IsZero() && row.Time.Equal(v.SourceOccurredAt) && !row.Time.Before(g.input.Window.Start) && row.Time.Before(g.input.Window.End) &&
			strings.EqualFold(row.Transport, "tcp") && strings.EqualFold(row.TCPState, "syn") && !row.OutcomeVerified &&
			row.Destination == v.Destination && row.Port == v.DestinationPort && row.Port != 0 && v.SourcePort != 0 &&
			row.SessionID != "" && row.SessionID == v.SessionID && srcErr == nil && dstErr == nil && src.Zone() == "" && dst.Zone() == "" &&
			!src.IsUnspecified() && !dst.IsUnspecified() && !src.IsMulticast() && !dst.IsMulticast() && src.Unmap().BitLen() == dst.Unmap().BitLen()
		if !valid {
			skipped++
			if row.SourceID != "" {
				poisoned[row.SourceID] = true
			}
			if v.SourceID != "" {
				poisoned[v.SourceID] = true
			}
			continue
		}
		identity := fmt.Sprintf("%s|%d|%s|%d|%d|%s|%s", src.Unmap(), v.SourcePort, dst.Unmap(), row.Port, v.Sequence, row.SessionID, row.Time.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"))
		if prior, ok := identities[row.SourceID]; ok && prior != identity {
			poisoned[row.SourceID] = true
		}
		identities[row.SourceID] = identity
		validRows = append(validRows, row)
	}
	sort.Slice(validRows, func(i, j int) bool {
		if validRows[i].Time.Equal(validRows[j].Time) {
			return validRows[i].SourceID < validRows[j].SourceID
		}
		return validRows[i].Time.Before(validRows[j].Time)
	})
	groups := map[string]*portAttemptGroup{}
	for _, row := range validRows {
		if poisoned[row.SourceID] {
			skipped++
			continue
		}
		v := row.SYNAttemptVerification
		src, _ := netip.ParseAddr(v.SourceAddress)
		dst, _ := netip.ParseAddr(v.Destination)
		key := g.scope.AssetID + "|" + g.scope.DeviceID + "|" + src.Unmap().String() + "|" + dst.Unmap().String()
		group := groups[key]
		if group == nil {
			group = &portAttemptGroup{seen: map[string]bool{}}
			groups[key] = group
		}
		// Do not use hit/IOC identity or capture time: retransmitted or reprojected
		// SYNs with the same TCP tuple and initial sequence are one attempt.
		attempt := fmt.Sprintf("%d|%d|%d", v.SourcePort, row.Port, v.Sequence)
		group.refs = append(group.refs, row.SourceID)
		if group.seen[attempt] {
			duplicates++
			continue
		}
		group.seen[attempt] = true
		group.rows = append(group.rows, row)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		f.Measurements.SampleCount += len(groups[key].rows)
	}
	f.Measurements.Values = map[string]float64{"excluded_attempt_projections": float64(skipped), "duplicate_attempt_projections": float64(duplicates), "source_target_groups": float64(len(groups))}
	var selected *Finding
	qualified, sampleCount := 0, 0
	qualifiedKeys := []string{}
	selectedKey := ""
	missingPolicy := false
	refs := []string{}
	for _, key := range keys {
		group := groups[key]
		candidate := e.portSequence(f, group.rows, group.refs)
		if candidate.Status == Missing {
			missingPolicy = missingPolicy || candidate.ReasonCode == MissingPolicy
			continue
		}
		qualified++
		qualifiedKeys = append(qualifiedKeys, key)
		sampleCount += len(group.rows)
		refs = append(refs, group.refs...)
		// Prefer a positive group, otherwise the largest qualified group; ties
		// retain the deterministic sorted group order. No cross-target sequence.
		if selected == nil || (candidate.Status == Observed && selected.Status != Observed) ||
			candidate.Status == selected.Status && candidate.Measurements.Values["distinct_ports"] > selected.Measurements.Values["distinct_ports"] {
			copy := candidate
			selected = &copy
			selectedKey = key
		}
	}
	f.Limitations = append(f.Limitations, fmt.Sprintf("Qualified source/target groups=%d; skipped projections=%d; duplicate/retransmitted projections=%d. Sequence metrics describe one selected group, never a merged target stream.", qualified, skipped, duplicates))
	if selected == nil {
		if len(groups) == 0 {
			return absent(f, UnresolvedBinding)
		}
		if missingPolicy {
			return absent(f, MissingPolicy)
		}
		return absent(f, InsufficientSamples)
	}
	result := *selected
	result.Limitations = append(result.Limitations, f.Limitations[len(f.Limitations)-1])
	result.Measurements.Labels = append(result.Measurements.Labels, "selected_source_target="+selectedKey)
	result.Measurements.SampleCount = sampleCount
	result.Measurements.Values["qualified_source_target_groups"] = float64(qualified)
	result.Measurements.Values["excluded_attempt_projections"] = float64(skipped)
	result.Measurements.Values["duplicate_attempt_projections"] = float64(duplicates)
	result.SourceIDs = unique(refs)
	sort.Strings(result.SourceIDs)
	var first, last = groups[keys[0]].rows[0].Time, groups[keys[0]].rows[0].Time
	// Only qualified groups contribute to the explicit observed-subset window.
	firstSet := false
	for _, key := range qualifiedKeys {
		group := groups[key]
		for _, row := range group.rows {
			if !firstSet || row.Time.Before(first) {
				first = row.Time
			}
			if !firstSet || row.Time.After(last) {
				last = row.Time
			}
			firstSet = true
		}
	}
	result.Window = &Window{Start: first, End: last, Convention: "verified_syn_attempt_subset_first_last_inclusive"}
	result.Dependencies = append(result.Dependencies, Dependency{Kind: "verified_tcp_syn_attempt_subset", Version: n.Version + ":" + TCPSYNAttemptVerificationVersion, SourceIDs: append([]string(nil), result.SourceIDs...)})
	return result
}
