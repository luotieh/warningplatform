package evidence

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

// CompressionOptions lets a report choose its presentation and relevance filter
// without making the normalization layer depend on report, storage or LLM code.
type CompressionOptions struct {
	MaxItems int
	MaxRunes int
	Eligible func(UnifiedEvidence) bool
	Project  func(UnifiedEvidence) any
}

type EvidenceDigest struct {
	Version            string         `json:"version"`
	TotalInstances     int            `json:"total_instances"`
	Counts             map[string]int `json:"status_counts"`
	GapReasons         map[string]int `json:"gap_reasons"`
	SelectedIDs        []string       `json:"selected_ids"`
	SelectedUnifiedIDs []string       `json:"selected_normalized_ids"`
	Omitted            int            `json:"compression_omitted"`
	InputRunes         int            `json:"selected_input_runes"`
}

// Compress drops whole results, never slices JSON or changes statuses/metrics.
// It preserves all counts and reasons and leaves the full index untouched.
func Compress(n NormalizedEvidence, opts CompressionOptions) EvidenceDigest {
	d := EvidenceDigest{Version: n.Version, TotalInstances: len(n.Items), Counts: n.Counts, GapReasons: n.Reasons, SelectedIDs: []string{}, SelectedUnifiedIDs: []string{}}
	items := append([]UnifiedEvidence(nil), n.Items...)
	priority := func(u UnifiedEvidence) int {
		if u.Kind == "fact" && u.Status == "observed" && strings.HasPrefix(u.RuleID, "F_HIST_") {
			return 0
		}
		if u.Kind == "semantic" && (strings.HasPrefix(u.RuleID, "R06/") || strings.HasPrefix(u.RuleID, "R07/")) {
			return 1
		}
		if u.Role == "measured_fact" {
			return 2
		}
		if u.Kind == "observation" {
			return 3
		}
		if u.Kind == "intelligence" {
			return 4
		}
		if u.Kind == "semantic" {
			return 5
		}
		return 6
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := priority(items[i]), priority(items[j])
		if a == b {
			return items[i].ReportID < items[j].ReportID
		}
		return a < b
	})
	for _, u := range items {
		if u.ReportID == "" || u.Role == "gap" || u.Role == "duplicate" || opts.Eligible != nil && !opts.Eligible(u) {
			continue
		}
		var payload any = u
		if opts.Project != nil {
			payload = opts.Project(u)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		size := utf8.RuneCount(raw)
		if len(d.SelectedIDs) >= opts.MaxItems || d.InputRunes+size > opts.MaxRunes {
			continue
		}
		d.SelectedIDs = append(d.SelectedIDs, u.ReportID)
		d.SelectedUnifiedIDs = append(d.SelectedUnifiedIDs, u.ID)
		d.InputRunes += size
	}
	d.Omitted = len(n.Items) - len(d.SelectedIDs)
	return d
}
