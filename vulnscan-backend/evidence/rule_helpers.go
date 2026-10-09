package evidence

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

func supported(id FactID) bool {
	for _, d := range definitions {
		if d.ID == id {
			return true
		}
	}
	return false
}
func groupRule(id FactID) bool {
	switch id {
	case "F_GROUP_NXDOMAIN_CLUSTER", "F_SHARED_DOMAIN_CLUSTER", "F_MULTI_ASSET_IOC", "F_MULTI_ASSET_DIST", "F_TIME_COORDINATION", "F_COORD_FANOUT", "F_INFECTION_CHAIN", "F_SHARED_ENDPOINT", "F_FIRST_VISIT_CLUSTER", "F_COORD_PATTERN_RECURRENCE":
		return true
	}
	return false
}
func stringPort(port uint16) string { return strconv.Itoa(int(port)) }
func baselineFrequency(g *observations, id FactID, key string) (float64, bool) {
	if g.input == nil {
		return 0, false
	}
	for _, b := range g.input.Baselines {
		if b.FactID == id && provenance(b.Provenance) && b.Complete {
			v, ok := b.Frequencies[key]
			return v, ok && finite(v) && v >= 0 && v <= 1
		}
	}
	return 0, false
}
func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func provenance(p Provenance) bool {
	if !p.Verified || p.Version == "" || len(p.SourceIDs) == 0 {
		return false
	}
	for _, s := range p.SourceIDs {
		if strings.TrimSpace(s) == "" {
			return false
		}
	}
	return true
}
func finish(f Finding, observed bool, values map[string]float64, refs ...string) Finding {
	f.Status = NotObserved
	f.Eligibility = "eligible"
	f.ReasonCode = ConditionsNotMet
	if observed {
		f.Status = Observed
		f.ReasonCode = ConditionsMet
	}
	f.Measurements.Values = values
	for _, r := range refs {
		if r != "" {
			f.SourceIDs = append(f.SourceIDs, r)
		}
	}
	sort.Strings(f.SourceIDs)
	f.SourceIDs = unique(f.SourceIDs)
	return f
}
func absent(f Finding, reason ReasonCode) Finding { f.ReasonCode = reason; return f }
func unique(items []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func (e *Engine) policy(f *Finding, name string) (float64, bool) {
	v, ok := e.config.Policies[f.FactID][name]
	if !ok || !finite(v) {
		return 0, false
	}
	if f.Parameters.Values == nil {
		f.Parameters.Values = map[string]float64{}
	}
	f.Parameters.Values[name] = v
	return v, true
}
func baseline(f *Finding, g *observations, names ...string) ([]float64, bool) {
	var records []Baseline
	if g.input != nil {
		records = g.input.Baselines
	}
	if g.group != nil {
		records = g.group.Baselines
	}
	for _, b := range records {
		if b.FactID != f.FactID || !provenance(b.Provenance) || !b.Complete {
			continue
		}
		values := []float64{}
		for _, name := range names {
			v, ok := b.Metrics[name]
			if !ok || !validBaselineMetric(name, v) {
				return nil, false
			}
			values = append(values, v)
		}
		f.SourceIDs = append(f.SourceIDs, b.SourceIDs...)
		dependency(f, "baseline", b.Provenance)
		return values, true
	}
	return nil, false
}

func dependency(f *Finding, kind string, p Provenance) {
	f.Dependencies = append(f.Dependencies, Dependency{Kind: kind, Version: p.Version, SourceIDs: append([]string(nil), p.SourceIDs...)})
}

func validBaselineMetric(name string, value float64) bool {
	if !finite(value) {
		return false
	}
	if name == "bigram_log_probability_p05" {
		return value <= 0
	}
	if value < 0 {
		return false
	}
	switch name {
	case "ua_frequency", "ua_frequency_p01", "port_frequency_p01", "infra_frequency_p01", "domain_frequency_p01", "endpoint_frequency", "endpoint_frequency_p01", "nxdomain_rate_p99", "group_nxdomain_rate_p99", "connection_failure_rate_p95", "unique_subdomain_ratio_p95", "unique_size_ratio_p05", "vowel_ratio_p05", "vowel_ratio_p95":
		return value <= 1
	}
	return true
}
func (e *Engine) additional(id FactID, g *observations) Finding {
	f := baseFinding(id, g, Parameters{}, []string{"仅描述已核验输入范围，不等于攻击成立；输入缺失不作为阴性证据"})
	if g.input != nil && g.input.Window != nil && g.input.Window.Start.Before(g.input.Window.End) {
		f.Window = &Window{Start: g.input.Window.Start.UTC(), End: g.input.Window.End.UTC(), Convention: "analysis_half_open"}
	}
	if groupRule(id) {
		return e.groupFact(f, g)
	}
	switch id {
	case "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_RATE_BURST", "F_RATE_RAMP":
		return e.timeFact(f, g)
	case "F_DNS_HIGH_ENTROPY", "F_DNS_ENCODED_LABEL", "F_DGA_LEXICAL", "F_NXDOMAIN_CLUSTER", "F_FAILED_TO_ACTIVE":
		return e.dnsFact(f, g)
	case "F_HTTP_ENDPOINT_REPEAT", "F_HTTP_FIELD_ENCODING", "F_HTTP_UA_RARITY", "F_HTTP_SIZE_STABILITY", "F_LONG_LOW_SESSION", "F_URL_ODD_AUTHORITY", "F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR", "F_CRED_POST_STRUCTURE", "F_FORM_CROSSSITE", "F_REDIRECT_CHAIN", "F_MULTI_REDIRECT_CHAIN":
		return e.httpFact(f, g)
	case "F_TLS_SNI_MISMATCH", "F_TLS_CERT_ANOMALY", "F_TLS_JA_MISMATCH":
		return e.tlsFact(f, g)
	case "F_HIST_ASSET_IOC_RECURRENCE", "F_HIST_GROUP_RECURRENCE", "F_HIST_INFRA_PERSISTENCE", "F_HIST_SCHEDULE_MATCH", "F_HIST_MULTI_IOC_SIEGE", "F_HIST_STAGE_PROGRESSION", "F_HIST_COORD_PARAM_MATCH", "F_HIST_EXERCISE", "F_IOC_NOVELTY", "F_EXCL_SCAN_TASK", "F_EXCL_INFRA_ROLE", "F_DST_NOVELTY":
		return e.historyFact(f, g)
	default:
		return e.networkFact(f, g)
	}
}
