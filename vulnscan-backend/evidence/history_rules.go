package evidence

import (
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func reviewed(event HistoryEvent) bool {
	return event.AdjudicationID != "" && (event.Adjudication == "malicious" || event.Adjudication == "false_positive") && (event.AdjudicationSource == "human" || event.AdjudicationSource == "host_evidence" || event.AdjudicationSource == "authoritative_external")
}
func validHistory(h *HistoryData, currentID string) bool {
	if h == nil || !provenance(h.Provenance) || !h.Complete || h.AsOf.IsZero() || h.LookbackStart.IsZero() || !h.LookbackStart.Before(h.AsOf) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range h.Events {
		if r.ID == "" || seen[r.ID] || r.ID == currentID || r.Time.Before(h.LookbackStart) || !r.Time.Before(h.AsOf) {
			return false
		}
		seen[r.ID] = true
		if r.Adjudication != "" && r.Adjudication != "unreviewed" && !reviewed(r) {
			return false
		}
	}
	return true
}
func (e *Engine) historyFact(f Finding, g *observations) Finding {
	if f.FactID == "F_EXCL_SCAN_TASK" || f.FactID == "F_EXCL_INFRA_ROLE" || f.FactID == "F_HIST_EXERCISE" {
		return e.authorization(f, g)
	}
	if g.input == nil || !validHistory(g.input.History, g.request.EventID) {
		return absent(f, MissingInput)
	}
	h := g.input.History
	dependency(&f, "history", h.Provenance)
	if !g.prepareTime() {
		return absent(f, InvalidTime)
	}
	if h.AsOf.After(g.times[0]) {
		return absent(f, UnresolvedBinding)
	}
	if f.FactID == "F_HIST_STAGE_PROGRESSION" {
		return e.stageProgression(f, g, h)
	}
	if f.FactID == "F_HIST_COORD_PARAM_MATCH" {
		return e.coordinationHistoryMatch(f, g, h)
	}
	refs := append([]string(nil), h.SourceIDs...)
	rows := []HistoryEvent{}
	for _, r := range h.Events {
		refs = append(refs, r.ID)
		if r.AdjudicationID != "" {
			refs = append(refs, r.AdjudicationID)
		}
		rows = append(rows, r)
	}
	if f.FactID == "F_HIST_ASSET_IOC_RECURRENCE" && h.LookbackStart.After(h.AsOf.AddDate(0, 0, -30)) {
		return absent(f, UnverifiedCoverage)
	}
	switch f.FactID {
	case "F_IOC_NOVELTY", "F_DST_NOVELTY":
		target := h.IOC
		if f.FactID == "F_DST_NOVELTY" {
			target = h.Endpoint
		}
		if target == "" {
			return absent(f, MissingInput)
		}
		matches := 0
		for _, r := range rows {
			if f.FactID == "F_IOC_NOVELTY" && r.IOC == target {
				matches++
			}
			if f.FactID == "F_DST_NOVELTY" && r.AssetID == g.scope.AssetID && r.Endpoint == target {
				matches++
			}
		}
		f.Limitations = append(f.Limitations, "仅表示声明覆盖的历史库内首次告警，不表示首次真实连接")
		return finish(f, matches == 0, map[string]float64{"prior_matches": float64(matches)}, refs...)
	case "F_HIST_ASSET_IOC_RECURRENCE":
		if h.IOC == "" {
			return absent(f, MissingInput)
		}
		days := map[string]bool{}
		count, malicious, benign, unknown := 0, 0, 0, 0
		for _, r := range rows {
			if r.AssetID != g.scope.AssetID || r.IOC != h.IOC || r.Time.Before(h.AsOf.AddDate(0, 0, -30)) {
				continue
			}
			count++
			days[r.Time.In(e.dayLocation).Format("2006-01-02")] = true
			switch r.Adjudication {
			case "malicious":
				malicious++
			case "false_positive":
				benign++
			default:
				unknown++
			}
		}
		f.Limitations = append(f.Limitations, "复发与历史定谳分别记录；未审核历史不证明恶意，不执行旧版加减分")
		return finish(f, count >= 2 && len(days) >= 2, map[string]float64{"independent_events": float64(count), "days_active": float64(len(days)), "malicious_adjudications": float64(malicious), "false_positive_adjudications": float64(benign), "unreviewed_events": float64(unknown)}, refs...)
	case "F_HIST_GROUP_RECURRENCE":
		if h.GroupID == "" || !h.GroupMembershipVerified || len(unique(h.CurrentMemberIDs)) < 3 {
			return absent(f, UnresolvedBinding)
		}
		weeks := map[string]bool{}
		matches := 0
		for _, r := range rows {
			if r.GroupID != h.GroupID || len(r.MemberIDs) == 0 {
				continue
			}
			if !sameSet(r.MemberIDs, h.CurrentMemberIDs) {
				continue
			}
			same := h.IOC != "" && r.IOC == h.IOC || h.Family != "" && r.Family == h.Family || h.Endpoint != "" && r.Endpoint == h.Endpoint
			if !same {
				continue
			}
			year, week := r.Time.In(e.dayLocation).ISOWeek()
			weeks[time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006")+"/"+stringPort(uint16(week))] = true
			matches++
		}
		return finish(f, len(weeks) >= 2, map[string]float64{"matching_events": float64(matches), "distinct_weeks": float64(len(weeks))}, refs...)
	case "F_HIST_INFRA_PERSISTENCE":
		if h.IOC == "" {
			return absent(f, MissingInput)
		}
		days, assets := map[string]bool{}, map[string]bool{}
		for _, r := range rows {
			if r.IOC == h.IOC {
				if r.AssetID == "" {
					return absent(f, MissingInput)
				}
				days[r.Time.In(e.dayLocation).Format("2006-01-02")] = true
				assets[r.AssetID] = true
			}
		}
		consecutive := consecutiveDays(days, e.dayLocation)
		return finish(f, consecutive >= 2 && len(assets) >= 2, map[string]float64{"days_active": float64(len(days)), "consecutive_days": float64(consecutive), "distinct_assets": float64(len(assets))}, refs...)
	case "F_HIST_SCHEDULE_MATCH":
		threshold, ok := e.policy(&f, "kl_threshold")
		if !ok || threshold < 0 {
			return absent(f, MissingPolicy)
		}
		past, current := make([]float64, 24), make([]float64, 24)
		n := 0
		for _, r := range rows {
			if r.AssetID == g.scope.AssetID && (h.IOC == "" || r.IOC == h.IOC) {
				past[r.Time.In(e.dayLocation).Hour()]++
				n++
			}
		}
		if n < 2 {
			return absent(f, InsufficientSamples)
		}
		for _, t := range g.times {
			current[t.In(e.dayLocation).Hour()]++
		}
		kl := 0.0
		divergent := 0
		for i, c := range current {
			p := c / float64(len(g.times))
			q := past[i] / float64(n)
			if p == 0 {
				continue
			}
			if q == 0 {
				divergent++
				continue
			}
			kl += p * math.Log(p/q)
		}
		return finish(f, divergent == 0 && kl < threshold, map[string]float64{"kl_divergence_finite_component": kl, "divergent_bins": float64(divergent)}, refs...)
	case "F_HIST_MULTI_IOC_SIEGE":
		b, ok := baseline(&f, g, "distinct_ioc_families_p99")
		if !ok {
			return absent(f, MissingBaseline)
		}
		iocs, families := map[string]bool{}, map[string]bool{}
		for _, r := range rows {
			if r.AssetID == g.scope.AssetID {
				if r.IOC != "" {
					iocs[r.IOC] = true
				}
				if r.RuleFamily != "" {
					families[r.RuleFamily] = true
				}
			}
		}
		count := max(len(iocs), len(families))
		return finish(f, count >= 3 && float64(count) > b[0], map[string]float64{"distinct_iocs": float64(len(iocs)), "distinct_rule_families": float64(len(families))}, refs...)
	}
	return absent(f, MissingInput)
}
func sameSet(a, b []string) bool {
	x, y := unique(a), unique(b)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
func (e *Engine) authorization(f Finding, g *observations) Finding {
	if g.input == nil || g.input.Authorizations == nil {
		return absent(f, MissingInput)
	}
	d := g.input.Authorizations
	dependency(&f, "authorizations", d.Provenance)
	if !provenance(d.Provenance) || !d.Complete {
		return absent(f, UnverifiedCoverage)
	}
	if !g.prepareTime() {
		return absent(f, InvalidTime)
	}
	refs := append([]string(nil), d.SourceIDs...)
	matches := 0
	for _, a := range d.Records {
		if a.ID == "" || !a.Start.Before(a.End) {
			return absent(f, MissingInput)
		}
		refs = append(refs, a.ID)
		if a.AssetID != g.scope.AssetID || g.times[0].Before(a.Start) || !g.times[len(g.times)-1].Before(a.End) {
			continue
		}
		if a.Endpoint != "" && a.Endpoint != g.scope.EndpointID {
			continue
		}
		if f.FactID == "F_HIST_EXERCISE" {
			if a.TaskType == "phishing_exercise" || a.TaskType == "test_platform" {
				if a.Endpoint == g.scope.EndpointID || matchedAuthorizationDomains(a, g) {
					matches++
				}
			}
			continue
		}
		if f.FactID == "F_EXCL_SCAN_TASK" && (a.Role != "scanner" || a.TaskType != "scan") {
			continue
		}
		if f.FactID == "F_EXCL_INFRA_ROLE" && (a.Role != "resolver" && a.Role != "proxy" && a.Role != "management") {
			continue
		}
		if g.input.Network == nil || !provenance(g.input.Network.Provenance) || !g.input.Network.Complete || len(a.Ports) == 0 || len(a.Protocols) == 0 || len(a.Targets) == 0 || a.Endpoint == "" {
			return absent(f, MissingInput)
		}
		match := true
		for _, r := range g.input.Network.Connections {
			portOK := false
			for _, port := range a.Ports {
				if r.Port == port {
					portOK = true
				}
			}
			protoOK := false
			for _, p := range a.Protocols {
				if strings.EqualFold(p, r.AppProtocol) {
					protoOK = true
				}
			}
			if !portOK || !protoOK || !r.ProtocolParsed || r.AssetID != a.AssetID || !authorizedTarget(r.Destination, a.Targets) || r.Time.Before(a.Start) || !r.Time.Before(a.End) {
				match = false
			}
		}
		if match && len(g.input.Network.Connections) > 0 {
			matches++
		}
	}
	f.Limitations = append(f.Limitations, "登记记录须与当前资产、时间及活动匹配；不自动取消其他证据或给出良性总判定")
	return finish(f, matches > 0, map[string]float64{"verified_matching_authorizations": float64(matches)}, refs...)
}
func matchedAuthorizationDomains(a AuthorizationRecord, g *observations) bool {
	if g.input.HTTP == nil || !provenance(g.input.HTTP.Provenance) {
		return false
	}
	matched := 0
	for _, r := range g.input.HTTP.Records {
		u, ok := parsedURL(r.URL)
		if ok {
			root, valid := registrable(u.Hostname())
			if valid && authorized(root, a.Domains) {
				matched++
				continue
			}
		}
		return false
	}
	return matched > 0
}

func consecutiveDays(days map[string]bool, location *time.Location) int {
	dates := []time.Time{}
	for day := range days {
		t, err := time.ParseInLocation("2006-01-02", day, location)
		if err == nil {
			dates = append(dates, t)
		}
	}
	sort.Slice(dates, func(i, j int) bool { return dates[i].Before(dates[j]) })
	best, current := 0, 0
	for i, t := range dates {
		if i > 0 && dates[i-1].AddDate(0, 0, 1).Equal(t) {
			current++
		} else {
			current = 1
		}
		if current > best {
			best = current
		}
	}
	return best
}
func authorizedTarget(target string, allowed []string) bool {
	for _, value := range allowed {
		if target == value {
			return true
		}
		prefix, err := netip.ParsePrefix(value)
		ip, e := netip.ParseAddr(target)
		if err == nil && e == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
