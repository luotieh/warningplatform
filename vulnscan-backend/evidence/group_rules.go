package evidence

import (
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

func verifiedGroup(g *observations) bool {
	x := g.group
	if x == nil || x.ID == "" || !provenance(x.Provenance) || !x.Complete || !x.Window.Start.Before(x.Window.End) {
		return false
	}
	seen := map[string]bool{}
	hits := g.hitIndex
	bound := map[string]bool{}
	for _, m := range x.Members {
		if !m.MembershipVerified || m.AssetID == "" || seen[m.AssetID] || m.AssetID != m.Scope.AssetID || len(m.HitIDs) == 0 {
			return false
		}
		seen[m.AssetID] = true
		for _, id := range m.HitIDs {
			h, ok := hits[id]
			if !ok || h.Scope != m.Scope || h.OccurredAt.IsZero() || h.OccurredAt.Before(x.Window.Start) || !h.OccurredAt.Before(x.Window.End) || bound[id] {
				return false
			}
			bound[id] = true
		}
	}
	for _, r := range x.Connections {
		if !seen[r.AssetID] || r.Time.Before(x.Window.Start) || !r.Time.Before(x.Window.End) || r.SourceID == "" || r.Destination == "" {
			return false
		}
	}
	for _, r := range x.DNS {
		if !seen[x.DNSOwnership[r.SourceID]] || r.Time.Before(x.Window.Start) || !r.Time.Before(x.Window.End) || r.SourceID == "" {
			return false
		}
	}
	return len(seen) > 0
}
func (e *Engine) groupFact(f Finding, g *observations) Finding {
	if !verifiedGroup(g) {
		return absent(f, UnresolvedBinding)
	}
	x := g.group
	dependency(&f, "group", x.Provenance)
	f.Window = &Window{Start: x.Window.Start.UTC(), End: x.Window.End.UTC(), Convention: "analysis_half_open"}
	f.Quality = "complete"
	refs := append([]string(nil), x.SourceIDs...)
	switch f.FactID {
	case "F_TIME_COORDINATION", "F_COORD_FANOUT", "F_INFECTION_CHAIN", "F_FIRST_VISIT_CLUSTER", "F_COORD_PATTERN_RECURRENCE":
		if x.Connections == nil {
			return absent(f, MissingInput)
		}
	}
	for _, m := range x.Members {
		refs = append(refs, m.HitIDs...)
	}
	for _, r := range x.Connections {
		refs = append(refs, r.SourceID)
	}
	for _, r := range x.DNS {
		refs = append(refs, r.SourceID)
	}
	if len(x.Members) < 3 {
		return finish(f, false, map[string]float64{"member_count": float64(len(x.Members))}, refs...)
	}
	switch f.FactID {
	case "F_GROUP_NXDOMAIN_CLUSTER":
		if len(x.DNS) == 0 {
			return absent(f, MissingInput)
		}
		b, ok := baseline(&f, g, "group_nxdomain_rate_p99")
		if !ok {
			return absent(f, MissingBaseline)
		}
		total, failed := map[string]int{}, map[string]int{}
		clusters := map[string]map[string]bool{}
		for _, r := range x.DNS {
			if !r.RCodeKnown {
				return absent(f, MissingInput)
			}
			asset := x.DNSOwnership[r.SourceID]
			total[asset]++
			if r.RCode == 3 {
				root, ok := registrable(r.Domain)
				if !ok {
					return absent(f, MissingInput)
				}
				failed[asset]++
				cluster := skeleton(strings.Split(root, ".")[0])
				pattern, ok := domainPattern(x, root)
				if !ok {
					return absent(f, MissingInput)
				}
				if pattern != "" {
					cluster = "pattern:" + pattern
				}
				if clusters[cluster] == nil {
					clusters[cluster] = map[string]bool{}
				}
				clusters[cluster][asset] = true
			}
		}
		matches := 0
		for _, members := range clusters {
			n := 0
			for asset := range members {
				if float64(failed[asset])/float64(total[asset]) > b[0] {
					n++
				}
			}
			if n >= 3 {
				matches++
			}
		}
		return finish(f, matches > 0, map[string]float64{"shared_failure_clusters": float64(matches)}, refs...)
	case "F_SHARED_DOMAIN_CLUSTER":
		if len(x.DNS) == 0 {
			return absent(f, MissingInput)
		}
		b, ok := baseline(&f, g, "domain_frequency_p01")
		if !ok {
			return absent(f, MissingBaseline)
		}
		members := map[string]map[string]bool{}
		for _, r := range x.DNS {
			root, ok := registrable(r.Domain)
			if !ok {
				return absent(f, MissingInput)
			}
			frequency, ok := groupFrequency(x, f.FactID, root)
			if !ok {
				return absent(f, MissingBaseline)
			}
			if frequency >= b[0] {
				continue
			}
			cluster := root
			pattern, valid := domainPattern(x, root)
			if !valid {
				return absent(f, MissingInput)
			}
			if pattern != "" {
				cluster = "pattern:" + pattern
			}
			if members[cluster] == nil {
				members[cluster] = map[string]bool{}
			}
			members[cluster][x.DNSOwnership[r.SourceID]] = true
		}
		best := 0
		for _, set := range members {
			if len(set) > best {
				best = len(set)
			}
		}
		if best < 3 && !x.DomainPatternsVerified {
			return absent(f, MissingInput)
		}
		return finish(f, best >= 3, map[string]float64{"shared_domain_assets": float64(best)}, refs...)
	case "F_MULTI_ASSET_IOC", "F_SHARED_ENDPOINT":
		target := x.IOC
		if f.FactID == "F_SHARED_ENDPOINT" {
			target = x.Endpoint
		}
		if target == "" {
			return absent(f, MissingInput)
		}
		members := map[string]bool{}
		times := []time.Time{}
		for _, r := range x.Connections {
			if r.Destination == target {
				members[r.AssetID] = true
				times = append(times, r.Time)
			}
		}
		for _, r := range x.DNS {
			if strings.EqualFold(strings.TrimSuffix(r.Domain, "."), target) {
				members[x.DNSOwnership[r.SourceID]] = true
				times = append(times, r.Time)
			}
		}
		if f.FactID == "F_SHARED_ENDPOINT" {
			b, ok := baseline(&f, g, "endpoint_frequency", "endpoint_frequency_p01")
			if !ok {
				return absent(f, MissingBaseline)
			}
			return finish(f, len(members) >= 3 && b[0] < b[1], map[string]float64{"endpoint_assets": float64(len(members)), "endpoint_frequency": b[0]}, refs...)
		}
		width, ok := e.policy(&f, "cluster_window_seconds")
		if !ok || width <= 0 {
			return absent(f, MissingPolicy)
		}
		span := timeSpan(times)
		return finish(f, len(members) >= 3 && span <= width, map[string]float64{"ioc_assets": float64(len(members)), "span_seconds": span}, refs...)
	case "F_MULTI_ASSET_DIST":
		minEntropy, ok := e.policy(&f, "subnet_entropy_min")
		if !ok || minEntropy < 0 {
			return absent(f, MissingPolicy)
		}
		counts := map[string]int{}
		management := true
		for _, m := range x.Members {
			if m.Subnet == "" || m.Role == "" {
				return absent(f, MissingInput)
			}
			counts[m.Subnet]++
			management = management && (m.Role == "management" || m.Role == "scanner")
		}
		h := 0.0
		for _, c := range counts {
			p := float64(c) / float64(len(x.Members))
			h -= p * math.Log2(p)
		}
		return finish(f, len(counts) >= 2 && h >= minEntropy && !management, map[string]float64{"subnets": float64(len(counts)), "subnet_entropy": h}, refs...)
	case "F_TIME_COORDINATION":
		step, ok := e.policy(&f, "bucket_seconds")
		if !ok || step <= 0 {
			return absent(f, MissingPolicy)
		}
		series, valid := groupSeries(x, step)
		if !valid {
			return absent(f, MissingInput)
		}
		maxLag := 0
		if v, exists := e.config.Policies[f.FactID]["max_lag_bins"]; exists {
			maxLag = int(v)
			f.Parameters.Values["max_lag_bins"] = v
		}
		if maxLag >= len(series[0])-2 {
			return absent(f, MissingPolicy)
		}
		minimum, valid := minimumLagCorrelation(series, maxLag)
		if !valid {
			return finish(f, false, map[string]float64{"variable_series": 0}, refs...)
		}
		return finish(f, minimum > 0.7, map[string]float64{"minimum_pair_correlation": minimum, "bucket_seconds": step}, refs...)
	case "F_COORD_FANOUT":
		return e.groupFanout(f, x, refs)
	case "F_INFECTION_CHAIN":
		if x.Endpoint == "" || len(x.Connections) == 0 {
			return absent(f, MissingInput)
		}
		width, ok := e.policy(&f, "chain_window_seconds")
		if !ok || width <= 0 {
			return absent(f, MissingPolicy)
		}
		for _, first := range x.Connections {
			if first.Destination != x.Endpoint {
				continue
			}
			for _, spread := range x.Connections {
				if spread.AssetID != first.AssetID || !spread.Time.After(first.Time) || spread.Time.Sub(first.Time).Seconds() > width {
					continue
				}
				for _, m := range x.Members {
					if m.AssetID == first.AssetID || !authorized(spread.Destination, m.Addresses) {
						continue
					}
					for _, last := range x.Connections {
						if last.AssetID == m.AssetID && last.Destination == x.Endpoint && last.Time.After(spread.Time) && last.Time.Sub(first.Time).Seconds() <= width {
							return finish(f, true, map[string]float64{"matched_chains": 1}, refs...)
						}
					}
				}
			}
		}
		return finish(f, false, map[string]float64{"matched_chains": 0}, refs...)
	case "F_FIRST_VISIT_CLUSTER":
		h := x.History
		if !validHistory(h, g.request.EventID) || !h.AsOf.Equal(x.Window.Start) || x.Endpoint == "" {
			return absent(f, MissingInput)
		}
		first := map[string]time.Time{}
		prior := map[string]bool{}
		for _, r := range h.Events {
			if r.Endpoint == x.Endpoint && r.Time.Before(x.Window.Start) {
				prior[r.AssetID] = true
			}
		}
		for _, r := range x.Connections {
			if r.Destination == x.Endpoint && !prior[r.AssetID] {
				if first[r.AssetID].IsZero() || r.Time.Before(first[r.AssetID]) {
					first[r.AssetID] = r.Time
				}
			}
		}
		times := []time.Time{}
		for _, t := range first {
			times = append(times, t)
		}
		return finish(f, len(first) >= 3 && timeSpan(times) <= 3600, map[string]float64{"first_visit_assets": float64(len(first)), "visit_span_seconds": timeSpan(times)}, append(refs, h.SourceIDs...)...)
	case "F_COORD_PATTERN_RECURRENCE":
		step, ok := e.policy(&f, "bucket_seconds")
		if !ok || step <= 0 {
			return absent(f, MissingPolicy)
		}
		days := map[string][]Connection{}
		for _, r := range x.Connections {
			day := r.Time.In(e.dayLocation).Format("2006-01-02")
			days[day] = append(days[day], r)
		}
		patterns := [][]float64{}
		for _, rows := range days {
			local := rows[0].Time.In(e.dayLocation)
			start := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, e.dayLocation)
			sub := *x
			sub.Window = AnalysisWindow{Start: start, End: start.AddDate(0, 0, 1)}
			sub.Connections = rows
			series, ok := groupSeries(&sub, step)
			if !ok {
				continue
			}
			corr, ok := minimumCorrelation(series)
			if !ok || corr <= 0.7 {
				continue
			}
			aggregate := make([]float64, len(series[0]))
			for _, s := range series {
				for i, v := range s {
					aggregate[i] += v
				}
			}
			patterns = append(patterns, aggregate)
		}
		for i, a := range patterns {
			for _, b := range patterns[i+1:] {
				if c, ok := correlation(a, b); ok && c > 0.7 {
					return finish(f, true, map[string]float64{"coordinated_days": float64(len(patterns)), "pattern_correlation": c}, refs...)
				}
			}
		}
		return finish(f, false, map[string]float64{"coordinated_days": float64(len(patterns))}, refs...)
	}
	return absent(f, MissingInput)
}

func domainPattern(x *GroupInput, domain string) (string, bool) {
	if len(x.DomainPatterns) == 0 {
		return "", true
	}
	if !x.DomainPatternsVerified {
		return "", false
	}
	matched := ""
	seen := map[string]bool{}
	for _, pattern := range x.DomainPatterns {
		if pattern.ID == "" || seen[pattern.ID] {
			return "", false
		}
		seen[pattern.ID] = true
		rx, err := regexp.Compile(pattern.Expression)
		if err != nil {
			return "", false
		}
		if rx.MatchString(domain) {
			if matched != "" {
				return "", false
			}
			matched = pattern.ID
		}
	}
	return matched, true
}
func timeSpan(times []time.Time) float64 {
	if len(times) < 2 {
		return 0
	}
	lo, hi := times[0], times[0]
	for _, t := range times {
		if t.Before(lo) {
			lo = t
		}
		if t.After(hi) {
			hi = t
		}
	}
	return hi.Sub(lo).Seconds()
}
func groupFrequency(x *GroupInput, id FactID, key string) (float64, bool) {
	for _, b := range x.Baselines {
		if b.FactID == id && provenance(b.Provenance) && b.Complete {
			v, ok := b.Frequencies[key]
			return v, ok && finite(v) && v >= 0 && v <= 1
		}
	}
	return 0, false
}
func groupSeries(x *GroupInput, step float64) ([][]float64, bool) {
	duration := x.Window.End.Sub(x.Window.Start).Seconds()
	n := int(math.Ceil(duration / step))
	if n < 3 || n > 2048 {
		return nil, false
	}
	rows := make([][]float64, len(x.Members))
	index := map[string]int{}
	for i, m := range x.Members {
		index[m.AssetID] = i
		rows[i] = make([]float64, n)
	}
	for _, r := range x.Connections {
		if x.Endpoint != "" && r.Destination != x.Endpoint {
			continue
		}
		i, ok := index[r.AssetID]
		j := int(r.Time.Sub(x.Window.Start).Seconds() / step)
		if !ok || j < 0 || j >= n {
			return nil, false
		}
		rows[i][j]++
	}
	return rows, true
}
func minimumCorrelation(series [][]float64) (float64, bool) {
	minimum := 1.0
	for i, a := range series {
		for _, b := range series[i+1:] {
			c, ok := correlation(a, b)
			if !ok {
				return 0, false
			}
			if c < minimum {
				minimum = c
			}
		}
	}
	return minimum, len(series) >= 3
}

func minimumLagCorrelation(series [][]float64, maxLag int) (float64, bool) {
	minimum := 1.0
	for i, a := range series {
		for _, b := range series[i+1:] {
			best := -2.0
			for lag := -maxLag; lag <= maxLag; lag++ {
				x, y := a, b
				if lag > 0 {
					x = a[lag:]
					y = b[:len(b)-lag]
				} else if lag < 0 {
					x = a[:len(a)+lag]
					y = b[-lag:]
				}
				if c, ok := correlation(x, y); ok && c > best {
					best = c
				}
			}
			if best < -1 {
				return 0, false
			}
			if best < minimum {
				minimum = best
			}
		}
	}
	return minimum, len(series) >= 3
}
func (e *Engine) groupFanout(f Finding, x *GroupInput, refs []string) Finding {
	sets := map[string]map[string]bool{}
	times := map[string][]time.Time{}
	for _, m := range x.Members {
		sets[m.AssetID] = map[string]bool{}
	}
	for _, r := range x.Connections {
		sets[r.AssetID][r.Destination+":"+stringPort(r.Port)] = true
		times[r.AssetID] = append(times[r.AssetID], r.Time)
	}
	minimum := 1.0
	for i, a := range x.Members {
		for _, b := range x.Members[i+1:] {
			intersection := 0
			for key := range sets[a.AssetID] {
				if sets[b.AssetID][key] {
					intersection++
				}
			}
			union := len(sets[a.AssetID]) + len(sets[b.AssetID]) - intersection
			if union == 0 {
				return absent(f, MissingInput)
			}
			ratio := float64(intersection) / float64(union)
			if ratio < minimum {
				minimum = ratio
			}
		}
	}
	if minimum > 0.7 {
		return finish(f, true, map[string]float64{"minimum_target_jaccard": minimum}, refs...)
	}
	gap, ok := e.policy(&f, "handoff_seconds")
	if !ok || gap < 0 {
		return absent(f, MissingPolicy)
	}
	type segment struct {
		lo, hi     uint32
		start, end time.Time
	}
	segments := []segment{}
	for _, m := range x.Members {
		ips := map[uint32]bool{}
		for _, r := range x.Connections {
			if r.AssetID != m.AssetID {
				continue
			}
			ip, err := netip.ParseAddr(r.Destination)
			if err != nil || !ip.Is4() {
				return finish(f, false, map[string]float64{"minimum_target_jaccard": minimum}, refs...)
			}
			a := ip.As4()
			v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
			ips[v] = true
		}
		if len(ips) == 0 {
			return absent(f, MissingInput)
		}
		lo, hi := uint32(math.MaxUint32), uint32(0)
		for v := range ips {
			if v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
		}
		if uint64(hi)-uint64(lo)+1 != uint64(len(ips)) {
			return finish(f, false, map[string]float64{"minimum_target_jaccard": minimum}, refs...)
		}
		ts := times[m.AssetID]
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		segments = append(segments, segment{lo: lo, hi: hi, start: ts[0], end: ts[len(ts)-1]})
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].lo < segments[j].lo })
	matched := true
	for i := 1; i < len(segments); i++ {
		delay := segments[i].start.Sub(segments[i-1].end).Seconds()
		matched = matched && uint64(segments[i-1].hi)+1 == uint64(segments[i].lo) && delay >= 0 && delay <= gap
	}
	return finish(f, matched, map[string]float64{"minimum_target_jaccard": minimum, "partition_segments": float64(len(segments))}, refs...)
}
