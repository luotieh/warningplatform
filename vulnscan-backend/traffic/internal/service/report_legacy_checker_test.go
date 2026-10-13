package service

import (
	"fmt"
	"regexp"
	"strings"
)

// Historical rules are test fixtures only and are not compiled into the server.
var reportUnsupportedNumbers = regexp.MustCompile(`[0-9０-９]|[零〇一二三四五六七八九十百千万亿两]+\s*(次|条|个|包|字节|秒|分钟|小时|天|%|％)`)
var reportOverclaims = regexp.MustCompile(`攻击成功|已[经]?失陷|已[经]?(植入|感染|窃取)|确认.{0,6}(失陷|感染|攻击成功)|成功.{0,4}(外传|投递|执行)|排除.{0,8}(C2|外传|周期|钓鱼)|没有.{0,8}(周期|外传|钓鱼)`)
var reportNegatedOverclaims = regexp.MustCompile(`(未能|尚未|不能|无法|不足以|未|没有证据|缺少证据)(直接|充分|独立)?(证明|确认|认定|表明|说明)(攻击成功|已失陷|已感染|已植入)|(不能|无法|尚不能|未能)(直接)?排除(C2|外传|周期通信|钓鱼)`)

// Historical checker retained for regression fixtures only. Report generation
// and saved-document reading no longer call it.
func validateReportAssessment(a ReportAssessment, b ReportEvidenceBundle) error {
	if a.Target != "malicious_activity" {
		return fmt.Errorf("report_target_invalid")
	}
	if _, exists := reportThreatTypeNames[a.ThreatType]; !exists {
		return fmt.Errorf("report_threat_type_invalid")
	}
	if a.Verdict != "suspicious" && a.Verdict != "likely_malicious" && a.Verdict != "likely_benign" && a.Verdict != "insufficient" {
		return fmt.Errorf("report_verdict_invalid")
	}
	if a.Stage != "contact" && a.Stage != "behavior" && a.Stage != "undetermined" {
		return fmt.Errorf("report_stage_invalid")
	}
	if a.Probability != nil && (*a.Probability < 0 || *a.Probability > 100) {
		return fmt.Errorf("report_probability_invalid")
	}
	if len(a.Supporting) > 8 || len(a.Opposing) > 8 || len(a.Alternatives) > 5 || len(a.Actions) > 8 || len(a.Gaps) > 8 {
		return fmt.Errorf("report_response_bounds")
	}
	if b.PolicyVersion == reportEvidenceVersion && (len(a.Risks) > 3 || len(b.SelectedIDs) > 0 && len(a.Risks) < 1) {
		return fmt.Errorf("report_risk_analysis_required")
	}
	if b.PolicyVersion == reportEvidenceVersion && len(b.SelectedIDs) > 0 && len(a.Actions) == 0 {
		return fmt.Errorf("report_protection_actions_required")
	}
	if a.Interpretations == nil || a.Supporting == nil || a.Opposing == nil || a.Alternatives == nil || a.Gaps == nil || a.Actions == nil {
		return fmt.Errorf("report_required_arrays_missing")
	}
	entries := map[string]ReportEvidence{}
	selected := map[string]bool{}
	for _, e := range b.Entries {
		if _, exists := entries[e.ID]; exists || e.ID == "" {
			return fmt.Errorf("report_evidence_identity_invalid")
		}
		entries[e.ID] = e
	}
	for _, id := range b.SelectedIDs {
		if _, exists := entries[id]; !exists || selected[id] {
			return fmt.Errorf("report_selected_evidence_invalid")
		}
		selected[id] = true
	}
	// A numeric token in prose is allowed only when it is a valid E-reference;
	// model-generated fact numbers are disallowed rather than loosely compared.
	textRefs := []string{}
	for _, r := range append(append(append([]ReportReason{}, a.Supporting...), a.Opposing...), a.Alternatives...) {
		textRefs = append(textRefs, r.EvidenceIDs...)
	}
	checkText := func(s string) error {
		if strings.TrimSpace(s) == "" || len([]rune(s)) > 500 {
			return fmt.Errorf("report_text_bounds")
		}
		if (strings.Contains(s, "项发现") || strings.Contains(s, "事实规则") || strings.Contains(s, "语义槽位") || strings.Contains(s, "证据算法")) && (strings.Contains(s, "未产出") || strings.Contains(s, "缺材料") || strings.Contains(s, "无法执行") || strings.Contains(s, "跳过")) {
			return fmt.Errorf("report_execution_diagnostics_require_appendix")
		}
		if reportOverclaims.MatchString(reportNegatedOverclaims.ReplaceAllString(s, "")) {
			return fmt.Errorf("report_success_or_exclusion_overclaim")
		}
		if b.PolicyVersion == reportEvidenceVersion {
			if err := validateReportBoundaries(s, textRefs, entries); err != nil {
				return err
			}
		}
		for id := range selected {
			s = strings.ReplaceAll(s, id, "")
		}
		return validateReportNumbers(s, textRefs, entries)
	}
	if err := checkText(a.ProbabilityReason); err != nil {
		return err
	}
	seenInterpretations := map[string]bool{}
	for _, i := range a.Interpretations {
		if !selected[i.EvidenceID] || seenInterpretations[i.EvidenceID] {
			return fmt.Errorf("report_interpretation_reference_invalid")
		}
		seenInterpretations[i.EvidenceID] = true
		textRefs = []string{i.EvidenceID}
		if err := checkText(i.Meaning); err != nil {
			return err
		}
	}
	if len(seenInterpretations) != len(selected) {
		return fmt.Errorf("report_interpretation_missing")
	}
	families := map[string]bool{}
	reasons := func(rs []ReportReason, role string) error {
		for _, r := range rs {
			textRefs = r.EvidenceIDs
			if len(r.EvidenceIDs) == 0 || len(r.EvidenceIDs) > 12 {
				return fmt.Errorf("report_reason_unbound")
			}
			if err := checkText(r.Explanation); err != nil {
				return err
			}
			seen := map[string]bool{}
			for _, id := range r.EvidenceIDs {
				e, ok := entries[id]
				if !ok || !selected[id] || seen[id] {
					return fmt.Errorf("report_unknown_or_duplicate_reference")
				}
				seen[id] = true
				if role == "supporting" {
					if e.Status == "not_observed" || e.Kind == "fact" && e.Status != "observed" || e.Kind == "semantic" && (e.Semantic == nil || e.Semantic.ExplanationOnly || e.Semantic.Judgement != "support") {
						return fmt.Errorf("report_invalid_support")
					}
					if families[e.Family] {
						return fmt.Errorf("report_duplicate_evidence_family")
					}
					families[e.Family] = true
				}
				if role == "opposing" {
					if e.Finding == nil || e.Finding.Status != "not_observed" || e.Finding.Eligibility != "eligible" || e.Finding.Quality != "complete" {
						return fmt.Errorf("report_invalid_counterevidence")
					}
				}
			}
		}
		return nil
	}
	if err := reasons(a.Supporting, "supporting"); err != nil {
		return err
	}
	if err := reasons(a.Opposing, "opposing"); err != nil {
		return err
	}
	if err := reasons(a.Alternatives, "alternatives"); err != nil {
		return err
	}
	for _, risk := range a.Risks {
		if err := reasons([]ReportReason{{EvidenceIDs: risk.EvidenceIDs, Explanation: risk.Exposure}}, "risk"); err != nil {
			return err
		}
		if !strings.HasPrefix(risk.Impact, "若") && !strings.HasPrefix(risk.Impact, "一旦") {
			return fmt.Errorf("report_risk_impact_must_be_conditional")
		}
		textRefs = risk.EvidenceIDs
		if err := checkText(risk.Impact); err != nil {
			return err
		}
	}
	if !reportTypeSupported(a, entries) {
		return fmt.Errorf("report_threat_type_without_evidence")
	}
	if b.Normalized.Version != "" {
		if err := validateHighReportProbability(a, entries); err != nil {
			return err
		}
	}
	for _, r := range a.Supporting {
		for _, id := range r.EvidenceIDs {
			e := entries[id]
			if e.Kind == "semantic" {
				for _, fact := range e.RelatedFactIDs {
					for _, other := range a.Supporting {
						for _, oid := range other.EvidenceIDs {
							if string(entries[oid].FactID) == fact && entries[oid].Scope == e.Scope {
								return fmt.Errorf("report_fact_semantic_double_count")
							}
						}
					}
				}
			}
		}
	}
	if a.Probability != nil && len(a.Supporting) == 0 && len(a.Opposing) == 0 {
		return fmt.Errorf("report_probability_without_evidence")
	}
	if a.Probability != nil && a.Verdict == "insufficient" {
		return fmt.Errorf("report_insufficient_verdict_with_probability")
	}
	if a.Verdict == "likely_malicious" {
		hasBehavior := false
		for _, r := range a.Supporting {
			for _, id := range r.EvidenceIDs {
				if entries[id].Kind == "fact" && entries[id].Status == "observed" {
					hasBehavior = true
				}
			}
		}
		if !hasBehavior {
			return fmt.Errorf("report_malicious_verdict_without_behavior")
		}
	}
	for _, g := range a.Gaps {
		textRefs = b.SelectedIDs
		if err := checkText(g); err != nil {
			return err
		}
	}
	for _, action := range a.Actions {
		textRefs = action.EvidenceIDs
		if err := checkText(action.Action); err != nil {
			return err
		}
		if err := checkText(action.Purpose); err != nil {
			return err
		}
		if len(action.EvidenceIDs) == 0 {
			return fmt.Errorf("report_action_unbound")
		}
		for _, id := range action.EvidenceIDs {
			if !selected[id] {
				return fmt.Errorf("report_action_unknown_reference")
			}
		}
	}
	return nil
}

func reportTypeSupported(a ReportAssessment, entries map[string]ReportEvidence) bool {
	if a.ThreatType == "undetermined" || a.ThreatType == "suspicious_contact" {
		return true
	}
	if a.ThreatType == "normal_business" {
		return a.Verdict == "likely_benign"
	}
	for _, reason := range a.Supporting {
		for _, id := range reason.EvidenceIDs {
			e := entries[id]
			if e.Kind == "intelligence" {
				terms := map[string][]string{"phishing_related": {"phishing", "钓鱼"}, "c2_related": {"command_and_control", "c2"}, "botnet_related": {"botnet", "僵尸网络"}, "mining_related": {"mining", "挖矿"}, "dns_related": {"dns_tunnel", "dns隧道"}, "exfiltration_related": {"exfiltration", "外传"}, "scanning_related": {"scanning", "扫描"}}
				for _, term := range terms[a.ThreatType] {
					if strings.Contains(strings.ToLower(e.Result), term) {
						return true
					}
				}
			}
			if e.Kind == "semantic" && e.Semantic != nil && e.Semantic.Judgement == "support" && !e.Semantic.ExplanationOnly {
				prefix := map[string]string{"phishing_related": "phishing.", "c2_related": "c2.", "botnet_related": "botnet.", "mining_related": "mining.", "exfiltration_related": "exfil."}[a.ThreatType]
				if prefix != "" && strings.HasPrefix(e.Semantic.Slot.Target, prefix) {
					return true
				}
			}
			if e.Kind == "fact" && e.Status == "observed" {
				fact := string(e.FactID)
				switch a.ThreatType {
				case "phishing_related":
					if strings.HasPrefix(fact, "F_URL_") || strings.HasPrefix(fact, "F_BRAND_") || strings.HasPrefix(fact, "F_CRED_") || strings.HasPrefix(fact, "F_FORM_") || strings.Contains(fact, "REDIRECT") {
						return true
					}
				case "c2_related":
					if strings.HasPrefix(fact, "F_BEACON_") || fact == "F_HTTP_ENDPOINT_REPEAT" {
						return true
					}
				case "botnet_related":
					if e.Scope.GroupID != "" {
						return true
					}
				case "mining_related":
					if strings.Contains(fact, "STRATUM") {
						return true
					}
				case "dns_related":
					if strings.HasPrefix(fact, "F_DNS_") || strings.HasPrefix(fact, "F_DGA_") || strings.Contains(fact, "NXDOMAIN") {
						return true
					}
				case "exfiltration_related":
					if strings.Contains(fact, "UPLOAD") || strings.Contains(fact, "OUTBOUND") {
						return true
					}
				case "scanning_related":
					if fact == "F_PORT_SEQUENCE" || strings.Contains(fact, "FANOUT") {
						return true
					}
				}
			}
		}
	}
	return false
}

// Additional report-only checks address actual failures found in client review.
// They are versioned so previously published documents remain reproducible.
func validateReportBoundaries(text string, refs []string, entries map[string]ReportEvidence) error {
	zeroPayload := false
	for _, id := range refs {
		e := entries[id]
		if (e.SavedDNSRecords > 0 || (e.Finding != nil && e.Finding.Measurements.Values["dns_records"] > 0)) && (strings.Contains(text, "持续通联") || strings.Contains(text, "历史通联") || strings.Contains(text, "历史通信")) {
			return fmt.Errorf("report_dns_association_not_transport_history")
		}
		if e.Finding != nil && e.Finding.Measurements.Values["zero_payload_fraction"] == 1 {
			zeroPayload = true
		}
		if strings.Contains(e.Result, "核验应用载荷总字节=0") {
			zeroPayload = true
		}
	}
	if !zeroPayload && (strings.Contains(text, "无载荷") || strings.Contains(text, "没有载荷")) {
		return fmt.Errorf("report_small_payload_not_zero_payload")
	}
	for _, phrase := range []string{"无跨日持续", "不存在跨日", "不符合持续性恶意", "确认观测数据完整性", "无异常规模", "查询自有域名属正常业务", "自有域名属于正常业务", "正常授权", "无恶意内容", "无异常传输", "TLS握手或心跳", "握手或心跳"} {
		if strings.Contains(text, phrase) {
			return fmt.Errorf("report_unsupported_scope_inference: %s", phrase)
		}
	}
	if strings.Contains(text, "白名单") && !strings.Contains(text, "核验") && !strings.Contains(text, "核对") {
		return fmt.Errorf("report_allowlist_requires_authorization_verification")
	}
	return nil
}
