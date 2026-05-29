package analyzer

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"vulnscan-backend/model"
)

type TamperAnalyzer struct {
	rules RuleAccessor
}

func NewTamperAnalyzer(rules RuleAccessor) *TamperAnalyzer {
	return &TamperAnalyzer{rules: rules}
}

func (a *TamperAnalyzer) Dimension() string { return "tamper" }

func (a *TamperAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}

	if snap.Error != "" {
		return output, nil
	}

	if needsBaselineInit(input.Baseline) {
		bodyText := tamperCompareText(snap)
		textLen := utf8.RuneCountInString(bodyText)

		trustedCDNs := a.loadTrustedDomains()
		suspicion := EvaluateBaselineSuspicion(snap, trustedCDNs)
		waybackResult := VerifyBaselineViaWayback(ctx, snap.URL, snap)
		crossResult := CrossValidateBaseline(ctx, snap)

		if waybackResult.Suspicious {
			suspicion.Score = min(suspicion.Score+20, 100)
			suspicion.Details = append(suspicion.Details, SuspicionFinding{
				Rule:     "wayback_mismatch",
				Severity: "high",
				Score:    20,
				Desc:     waybackResult.Reason,
			})
		}
		if crossResult.Suspicious {
			suspicion.Score = min(suspicion.Score+crossResult.Score, 100)
			for _, reason := range crossResult.Reasons {
				suspicion.Details = append(suspicion.Details, SuspicionFinding{
					Rule:     "cross_validate",
					Severity: "medium",
					Score:    crossResult.Score,
					Desc:     reason,
				})
			}
		}

		output.BaselineUpdate = &model.MonitorBaselineUpdate{
			ContentHash:       snap.ContentHash,
			Simhash:           int64(Simhash(bodyText)),
			DomStructureHash:  fmt.Sprintf("%x", md5.Sum([]byte(extractDOMStructure(snap.RenderedHTML)))),
			Title:             snap.Title,
			StatusCode:        snap.StatusCode,
			VisibleTextLength: textLen,
			BodyText:          bodyText,
			Action:            "init",
			SuspicionScore:    suspicion.Score,
			SuspicionDetail:   suspicion.DetailJSON(),
		}
		evidence := buildTamperFirstRunEvidence(bodyText)
		detailJSON, _ := json.Marshal(map[string]any{
			"is_first_run":        true,
			"title":               snap.Title,
			"status_code":         snap.StatusCode,
			"content_hash":        snap.ContentHash,
			"visible_text_length": textLen,
			"url":                 firstNonEmptyStr(snap.URL),
			"evidence":            evidence,
			"suspicion":           suspicion,
			"wayback":             waybackResult,
			"cross_validation":    crossResult,
		})
		output.DetailsJSON = string(detailJSON)
		return output, nil
	}

	currentText := tamperCompareText(snap)
	diffs := a.compareWithBaseline(snap, input.Baseline)
	evidence := buildTamperCompareEvidence(input.Baseline.BodyText, currentText)

	if len(diffs) > 0 {
		crossCheck := a.crossValidateWithOtherDimensions(ctx, input.SnapshotJSON, input.URL)
		textLen := utf8.RuneCountInString(currentText)

		isNormalUpdate := crossCheck != nil && !crossCheck.HasMaliciousContent && !hasInjectedElements(diffs)

		if isNormalUpdate {
			output.HasIssue = false
			output.Severity = "info"
			output.BaselineUpdate = &model.MonitorBaselineUpdate{
				ContentHash:       snap.ContentHash,
				Simhash:           int64(Simhash(currentText)),
				DomStructureHash:  fmt.Sprintf("%x", md5.Sum([]byte(extractDOMStructure(snap.RenderedHTML)))),
				Title:             snap.Title,
				StatusCode:        snap.StatusCode,
				VisibleTextLength: textLen,
				BodyText:          currentText,
				Action:            "auto_accept",
			}
		} else {
			output.HasIssue = true
			output.Severity = classifyTamperSeverityWithCross(diffs, crossCheck)
		}

		detailMap := map[string]any{
			"diffs":               diffs,
			"title":               snap.Title,
			"status_code":         snap.StatusCode,
			"content_hash":        snap.ContentHash,
			"visible_text_length": textLen,
			"evidence":            evidence,
		}
		if crossCheck != nil {
			detailMap["cross_validation"] = crossCheck
		}
		if isNormalUpdate {
			detailMap["auto_accepted"] = true
			detailMap["likely_normal_update"] = true
		}
		detailJSON, _ := json.Marshal(detailMap)
		output.DetailsJSON = string(detailJSON)
	} else if evidence.BaselineHTML != "" || evidence.CurrentHTML != "" {
		detailJSON, _ := json.Marshal(map[string]any{
			"evidence": evidence,
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

func (a *TamperAnalyzer) compareWithBaseline(snap *snapshotData, baseline *model.MonitorBaseline) []map[string]any {
	diffs := make([]map[string]any, 0)

	if snap.ContentHash != baseline.ContentHash && baseline.ContentHash != "" {
		currentText := tamperCompareText(snap)
		currentSimhash := Simhash(currentText)
		baselineSimhash := uint64(baseline.Simhash)
		similarity := SimhashSimilarity(currentSimhash, baselineSimhash)
		distance := SimhashDistance(currentSimhash, baselineSimhash)

		changeScale := "major"
		if similarity > 0.95 {
			changeScale = "trivial"
		} else if similarity > 0.85 {
			changeScale = "minor"
		} else if similarity > 0.70 {
			changeScale = "moderate"
		}

		diffs = append(diffs, map[string]any{
			"type":               "content_hash",
			"baseline":           baseline.ContentHash,
			"current":            snap.ContentHash,
			"simhash_similarity": similarity,
			"simhash_distance":   distance,
			"change_scale":       changeScale,
		})
	}

	if snap.Title != baseline.Title && baseline.Title != "" {
		diffs = append(diffs, map[string]any{
			"type":     "title",
			"baseline": baseline.Title,
			"current":  snap.Title,
		})
	}

	if snap.StatusCode != baseline.StatusCode && baseline.StatusCode > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "status_code",
			"baseline": baseline.StatusCode,
			"current":  snap.StatusCode,
		})
	}

	if baseline.VisibleTextLength > 0 {
		diff := len(snap.VisibleText) - baseline.VisibleTextLength
		ratio := float64(absInt(diff)) / float64(baseline.VisibleTextLength)
		if ratio > 0.3 {
			diffs = append(diffs, map[string]any{
				"type":     "text_length",
				"baseline": baseline.VisibleTextLength,
				"current":  len(snap.VisibleText),
				"ratio":    ratio,
			})
		}
	}

	injected := a.checkInjectedElements(snap)
	if len(injected) > 0 {
		diffs = append(diffs, map[string]any{
			"type":     "injected_elements",
			"elements": injected,
		})
	}

	return diffs
}

func (a *TamperAnalyzer) checkInjectedElements(snap *snapshotData) []map[string]any {
	findings := make([]map[string]any, 0)
	trustedCDNs := a.loadTrustedDomains()

	for _, script := range snap.Scripts {
		if script.IsExternal && script.Src != "" {
			domain := extractHost(script.Src)
			pageDomain := extractHost(snap.URL)
			if domain != "" && pageDomain != "" && domain != pageDomain &&
				!matchTrustedDomain(domain, trustedCDNs) {
				findings = append(findings, map[string]any{
					"type":   "external_script",
					"src":    script.Src,
					"domain": domain,
				})
			}
		}
	}

	return findings
}

func (a *TamperAnalyzer) loadTrustedDomains() []string {
	if a.rules == nil {
		return nil
	}
	data, err := a.rules.GetModuleRules("tamper")
	if err != nil || len(data) == 0 {
		return nil
	}
	var cfg struct {
		TrustedDomains []struct {
			Domain string `json:"domain"`
		} `json:"trusted_domains"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	domains := make([]string, 0, len(cfg.TrustedDomains))
	for _, d := range cfg.TrustedDomains {
		if d.Domain != "" {
			domains = append(domains, d.Domain)
		}
	}
	return domains
}

func matchTrustedDomain(domain string, trusted []string) bool {
	for _, t := range trusted {
		if domain == t || strings.HasSuffix(domain, "."+t) {
			return true
		}
	}
	return false
}

func extractDOMStructure(htmlStr string) string {
	var buf strings.Builder
	inTag := false
	for _, ch := range htmlStr {
		if ch == '<' {
			inTag = true
			buf.WriteRune(ch)
		} else if ch == '>' {
			inTag = false
			buf.WriteRune(ch)
		} else if inTag {
			if ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
				continue
			}
			buf.WriteRune(ch)
		}
	}
	return buf.String()
}

// needsBaselineInit 无基线或仅有历史 hash、无正文时，只建基线，不做篡改判定。
func needsBaselineInit(b *model.MonitorBaseline) bool {
	if b == nil {
		return true
	}
	if strings.TrimSpace(b.BodyText) == "" {
		return true
	}
	return strings.TrimSpace(b.ContentHash) == "" &&
		strings.TrimSpace(b.Title) == "" &&
		b.StatusCode == 0 &&
		b.VisibleTextLength == 0 &&
		strings.TrimSpace(b.DomStructureHash) == ""
}

func isEmptyBaseline(b *model.MonitorBaseline) bool {
	return needsBaselineInit(b)
}

// TamperCrossCheck holds the result of cross-validating a tampered page against
// sensitive word and blacklink analyzers. If malicious content is detected, the
// tamper is confirmed as hostile; otherwise it is likely a legitimate update.
type TamperCrossCheck struct {
	HasMaliciousContent bool   `json:"has_malicious_content"`
	SensitiveWordHit    bool   `json:"sensitive_word_hit"`
	BlacklinkHit        bool   `json:"blacklink_hit"`
	Summary             string `json:"summary"`
}

func (a *TamperAnalyzer) crossValidateWithOtherDimensions(ctx context.Context, snapshotJSON, url string) *TamperCrossCheck {
	if a.rules == nil {
		return nil
	}

	result := &TamperCrossCheck{}

	swAnalyzer := NewSensitiveWordAnalyzer(a.rules)
	swInput := &Input{SnapshotJSON: snapshotJSON, URL: url}
	if swOut, err := swAnalyzer.Analyze(ctx, swInput); err == nil && swOut != nil && swOut.HasIssue {
		result.SensitiveWordHit = true
		result.HasMaliciousContent = true
	}

	blAnalyzer := NewBlacklinkAnalyzer(a.rules)
	blInput := &Input{SnapshotJSON: snapshotJSON, URL: url}
	if blOut, err := blAnalyzer.Analyze(ctx, blInput); err == nil && blOut != nil && blOut.HasIssue {
		result.BlacklinkHit = true
		result.HasMaliciousContent = true
	}

	var parts []string
	if result.SensitiveWordHit {
		parts = append(parts, "检出敏感词")
	}
	if result.BlacklinkHit {
		parts = append(parts, "检出暗链")
	}
	if len(parts) > 0 {
		result.Summary = "确认篡改: " + strings.Join(parts, "、")
	} else {
		result.Summary = "未检出敏感词/暗链，可能为正常更新"
	}
	return result
}

func classifyTamperSeverityWithCross(diffs []map[string]any, cross *TamperCrossCheck) string {
	hasInjection := false
	for _, d := range diffs {
		if d["type"] == "injected_elements" {
			hasInjection = true
			break
		}
	}

	if hasInjection {
		return "critical"
	}

	if cross != nil && cross.HasMaliciousContent {
		return "critical"
	}

	if cross != nil && !cross.HasMaliciousContent {
		if isTrivialChange(diffs) {
			return "info"
		}
		return "low"
	}

	if len(diffs) >= 3 {
		return "high"
	}
	return "medium"
}

func classifyTamperSeverity(diffs []map[string]any) string {
	return classifyTamperSeverityWithCross(diffs, nil)
}

func hasInjectedElements(diffs []map[string]any) bool {
	for _, d := range diffs {
		if d["type"] == "injected_elements" {
			return true
		}
	}
	return false
}

func isTrivialChange(diffs []map[string]any) bool {
	for _, d := range diffs {
		if scale, ok := d["change_scale"].(string); ok && scale == "trivial" {
			return true
		}
	}
	return false
}
