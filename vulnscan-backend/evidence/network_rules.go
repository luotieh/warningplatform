package evidence

import (
	"math"
	"sort"
	"strings"
	"time"
)

func (e *Engine) networkFact(f Finding, g *observations) Finding {
	switch f.FactID {
	case "F_INDEPENDENT_RULE_CORROB", "F_INDEPENDENT_INTEL_CORROB", "F_IOC_TYPE_CORROB":
		return e.corroboration(f, g)
	}
	if g.input == nil || g.input.Network == nil {
		return absent(f, MissingInput)
	}
	n := g.input.Network
	dependency(&f, "network", n.Provenance)
	if !provenance(n.Provenance) || !n.Complete || len(n.Connections) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	f.SourceIDs = append(f.SourceIDs, n.SourceIDs...)
	refs := []string{}
	for _, r := range n.Connections {
		if r.SourceID == "" || r.Time.IsZero() || r.AssetID != g.scope.AssetID || r.Destination == "" {
			return absent(f, UnresolvedBinding)
		}
		refs = append(refs, r.SourceID)
	}
	switch f.FactID {
	case "F_PROTOCOL_PORT_MISMATCH":
		if !n.ServicesVerified || len(n.Services) == 0 {
			return absent(f, MissingInput)
		}
		count := 0
		for _, r := range n.Connections {
			if !r.ProtocolParsed || r.AppProtocol == "" {
				return absent(f, MissingInput)
			}
			known := false
			match := false
			for _, s := range n.Services {
				if s.Port == r.Port {
					known = true
					if strings.EqualFold(s.Protocol, r.AppProtocol) {
						match = true
					}
				}
			}
			if !known {
				return absent(f, MissingInput)
			}
			if !match {
				count++
			}
		}
		return finish(f, count > 0, map[string]float64{"protocol_service_mismatches": float64(count)}, refs...)
	case "F_RARE_PORT":
		b, ok := baseline(&f, g, "port_frequency_p01")
		if !ok {
			return absent(f, MissingBaseline)
		}
		found := 0
		for _, r := range n.Connections {
			key := stringPort(r.Port)
			frequency, ok := baselineFrequency(g, f.FactID, key)
			if !ok {
				return absent(f, MissingBaseline)
			}
			if frequency < b[0] {
				found++
			}
		}
		return finish(f, found > 0, map[string]float64{"rare_port_connections": float64(found)}, refs...)
	case "F_INFRA_RARITY":
		if n.ASN == "" || n.Country == "" || n.Reputation == "" {
			return absent(f, MissingInput)
		}
		b, ok := baseline(&f, g, "infra_frequency_p01")
		if !ok {
			return absent(f, MissingBaseline)
		}
		frequency, ok := baselineFrequency(g, f.FactID, n.ASN+"|"+n.Country+"|"+n.Reputation)
		if !ok {
			return absent(f, MissingBaseline)
		}
		return finish(f, frequency < b[0], map[string]float64{"infrastructure_frequency": frequency}, refs...)
	case "F_FANOUT_SINGLE_SRC":
		b, ok := baseline(&f, g, "unique_targets_per_hour_p99")
		if !ok {
			return absent(f, MissingBaseline)
		}
		w := g.input.Window
		if w == nil || !w.Start.Before(w.End) || w.Start.Truncate(time.Hour) != w.Start || w.End.Truncate(time.Hour) != w.End {
			return absent(f, MissingInput)
		}
		buckets := map[time.Time]map[string]bool{}
		for _, r := range n.Connections {
			if r.Time.Before(w.Start) || !r.Time.Before(w.End) {
				return absent(f, UnresolvedBinding)
			}
			t := r.Time.UTC().Truncate(time.Hour)
			if buckets[t] == nil {
				buckets[t] = map[string]bool{}
			}
			buckets[t][r.Destination+":"+stringPort(r.Port)] = true
		}
		peak := 0
		for _, targets := range buckets {
			if len(targets) > peak {
				peak = len(targets)
			}
		}
		return finish(f, float64(peak) > b[0], map[string]float64{"peak_unique_targets_per_hour": float64(peak)}, refs...)
	case "F_PORT_SEQUENCE":
		rows := append([]Connection(nil), n.Connections...)
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Time.Equal(rows[j].Time) {
				return rows[i].SourceID < rows[j].SourceID
			}
			return rows[i].Time.Before(rows[j].Time)
		})
		seen := map[uint16]bool{}
		ports := []float64{}
		for _, r := range rows {
			if !seen[r.Port] {
				seen[r.Port] = true
				ports = append(ports, float64(r.Port))
			}
		}
		if len(ports) < 8 {
			return absent(f, InsufficientSamples)
		}
		ascending, descending := true, true
		for i := 1; i < len(ports); i++ {
			ascending = ascending && ports[i] > ports[i-1]
			descending = descending && ports[i] < ports[i-1]
		}
		if ascending || descending {
			return finish(f, true, map[string]float64{"distinct_ports": float64(len(ports)), "monotonic": 1}, refs...)
		}
		threshold, ok := e.policy(&f, "difference_entropy_threshold")
		if !ok || threshold <= 0 {
			return absent(f, MissingPolicy)
		}
		counts := map[float64]int{}
		for i := 1; i < len(ports); i++ {
			counts[ports[i]-ports[i-1]]++
		}
		h := 0.0
		for _, c := range counts {
			p := float64(c) / float64(len(ports)-1)
			h -= p * math.Log2(p)
		}
		f.Limitations = append(f.Limitations, "差分熵仅为配置的伪随机序列线索，不证明随机生成机制")
		return finish(f, h >= threshold, map[string]float64{"distinct_ports": float64(len(ports)), "difference_entropy": h}, refs...)
	case "F_SMALL_PACKET":
		limit, ok := e.policy(&f, "small_payload_bytes")
		if !ok || limit <= 0 {
			return absent(f, MissingPolicy)
		}
		small := 0
		for _, r := range n.Connections {
			if r.PayloadBytes == nil {
				return absent(f, MissingInput)
			}
			if float64(*r.PayloadBytes) <= limit {
				small++
			}
		}
		ratio := float64(small) / float64(len(n.Connections))
		return finish(f, ratio >= 0.8, map[string]float64{"small_payload_fraction": ratio}, refs...)
	case "F_CONN_FAIL_RATE":
		b, ok := baseline(&f, g, "connection_failure_rate_p95")
		if !ok || b[0] < 0 || b[0] > 1 {
			return absent(f, MissingBaseline)
		}
		failed := 0
		for _, r := range n.Connections {
			switch strings.ToUpper(r.TCPState) {
			case "RST", "TIMEOUT", "SYN_SENT":
				failed++
			case "ESTABLISHED", "CLOSED":
			default:
				return absent(f, MissingInput)
			}
		}
		rate := float64(failed) / float64(len(n.Connections))
		return finish(f, rate > b[0], map[string]float64{"connection_failure_rate": rate}, refs...)
	}
	return absent(f, MissingInput)
}

func (e *Engine) corroboration(f Finding, g *observations) Finding {
	if g.input == nil || g.input.Corroboration == nil {
		return absent(f, MissingInput)
	}
	c := g.input.Corroboration
	dependency(&f, "corroboration", c.Provenance)
	if !provenance(c.Provenance) || !c.Complete {
		return absent(f, UnverifiedCoverage)
	}
	refs := append([]string(nil), c.SourceIDs...)
	switch f.FactID {
	case "F_INDEPENDENT_RULE_CORROB":
		if len(c.Rules) == 0 {
			return absent(f, MissingInput)
		}
		groups, origins := map[string]bool{}, map[string]bool{}
		for _, r := range c.Rules {
			if r.ID == "" || r.IndependenceGroup == "" || r.OriginalSource == "" {
				return absent(f, MissingInput)
			}
			groups[r.IndependenceGroup] = true
			origins[r.OriginalSource] = true
			refs = append(refs, r.ID)
		}
		return finish(f, len(groups) >= 2 && len(origins) >= 2, map[string]float64{"independence_groups": float64(len(groups)), "original_sources": float64(len(origins))}, refs...)
	case "F_INDEPENDENT_INTEL_CORROB":
		if c.IOC == "" || len(c.Intelligence) == 0 {
			return absent(f, MissingInput)
		}
		sources := map[string]bool{}
		for _, r := range c.Intelligence {
			if r.ID == "" || r.OriginalSource == "" || r.IOC != c.IOC {
				return absent(f, UnresolvedBinding)
			}
			sources[r.OriginalSource] = true
			refs = append(refs, r.ID)
		}
		return finish(f, len(sources) >= 2, map[string]float64{"independent_intelligence_sources": float64(len(sources))}, refs...)
	case "F_IOC_TYPE_CORROB":
		if !c.HardScoresVerified || c.IOCType == "" || len(c.HardTypeScores) == 0 {
			return absent(f, MissingInput)
		}
		types := []string{"C2", "BT", "PH"}
		total := 0.0
		for key, value := range c.HardTypeScores {
			if !finite(value) || value < 0 || (key != "C2" && key != "BT" && key != "PH") {
				return absent(f, MissingInput)
			}
		}
		sort.SliceStable(types, func(i, j int) bool { return c.HardTypeScores[types[i]] > c.HardTypeScores[types[j]] })
		for _, name := range types {
			total += c.HardTypeScores[name]
		}
		first, second := c.HardTypeScores[types[0]], c.HardTypeScores[types[1]]
		share := 0.0
		if total > 0 {
			share = first / total
		}
		return finish(f, first >= 15 && share >= 0.6 && first-second >= 10 && c.IOCType == types[0], map[string]float64{"hard_type_top1": first, "top1_share": share, "margin": first - second}, refs...)
	}
	return absent(f, MissingInput)
}
