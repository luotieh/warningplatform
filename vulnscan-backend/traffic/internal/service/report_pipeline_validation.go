package service

import (
	"fmt"
	"regexp"
	"strings"
)

const pipelineReportValidation = "pipeline_v2_references_boundaries_and_numbers"

var pipelineSuccessClaim = regexp.MustCompile(`攻击成功|已[经]?失陷|已[经]?(植入|感染|窃取)|确认.{0,6}(失陷|感染|攻击成功)|成功.{0,4}(外传|投递|执行)`)
var pipelineSuccessQualification = regexp.MustCompile(`(未能|尚未|不能|无法|不足以|未|没有证据|缺少证据)(直接|充分|独立)?(证明|确认|认定|表明|说明)(攻击成功|已失陷|已感染|已植入)`)

// Validate only the actual bounded model projection. Diagnostic, omitted and
// arbitrary IDs cannot authorize prose. No probability formula or minimum is
// introduced here; backend F/C values never come from this model response.
func validatePipelineAssessment(a ReportAssessment, b ReportEvidenceBundle) error {
	if a.Target != "malicious_activity" {
		return fmt.Errorf("report_target_invalid")
	}
	if _, ok := reportThreatTypeNames[a.ThreatType]; !ok {
		return fmt.Errorf("report_threat_type_invalid")
	}
	if a.Verdict != "suspicious" && a.Verdict != "likely_malicious" && a.Verdict != "likely_benign" && a.Verdict != "insufficient" {
		return fmt.Errorf("report_verdict_invalid")
	}
	if a.Stage != "contact" && a.Stage != "behavior" && a.Stage != "undetermined" {
		return fmt.Errorf("report_stage_invalid")
	}
	entries := map[string]ReportEvidence{}
	for _, item := range b.Entries {
		entries[item.ID] = item
	}
	allowed := map[string]bool{}
	for _, item := range reportEssenceFor(b).Items {
		allowed[item.ID] = true
	}
	checkRefs := func(refs []string) error {
		if len(refs) == 0 || len(refs) > 32 {
			return fmt.Errorf("report_reason_unbound")
		}
		seen := map[string]bool{}
		for _, ref := range refs {
			if !allowed[ref] || seen[ref] {
				return fmt.Errorf("report_unknown_or_duplicate_reference")
			}
			seen[ref] = true
		}
		return nil
	}
	checkText := func(text string, refs []string, conditional bool) error {
		if strings.TrimSpace(text) == "" || len([]rune(text)) > 2000 {
			return fmt.Errorf("report_text_bounds")
		}
		if !conditional && pipelineSuccessClaim.MatchString(pipelineSuccessQualification.ReplaceAllString(text, "")) {
			return fmt.Errorf("report_success_overclaim")
		}
		return validateReportNumbers(text, refs, entries)
	}
	allRefs := []string{}
	for group, reasons := range [][]ReportReason{a.Supporting, a.Opposing, a.Alternatives} {
		if len(reasons) > 16 {
			return fmt.Errorf("report_response_bounds")
		}
		for _, reason := range reasons {
			if err := checkRefs(reason.EvidenceIDs); err != nil {
				return err
			}
			if err := checkText(reason.Explanation, reason.EvidenceIDs, false); err != nil {
				return err
			}
			for _, ref := range reason.EvidenceIDs {
				e := entries[ref]
				if group == 0 && (e.Kind == "fact" && e.Status != "observed" || e.Kind == "semantic" && (e.Semantic == nil || e.Semantic.Judgement != "support")) {
					return fmt.Errorf("report_invalid_support")
				}
				if group == 1 && (e.Finding == nil || e.Finding.Status != "not_observed" || e.Finding.Eligibility != "eligible" || e.Finding.Quality != "complete") {
					return fmt.Errorf("report_invalid_counterevidence")
				}
			}
			if group < 2 {
				allRefs = append(allRefs, reason.EvidenceIDs...)
			}
		}
	}
	if len(allRefs) == 0 {
		return fmt.Errorf("report_probability_without_evidence")
	}
	if err := checkText(a.ProbabilityReason, allRefs, false); err != nil {
		return err
	}
	for _, item := range a.Interpretations {
		if err := checkRefs([]string{item.EvidenceID}); err != nil {
			return err
		}
		if err := checkText(item.Meaning, []string{item.EvidenceID}, false); err != nil {
			return err
		}
	}
	for _, gap := range a.Gaps {
		if pipelineSuccessClaim.MatchString(pipelineSuccessQualification.ReplaceAllString(gap, "")) {
			return fmt.Errorf("report_success_overclaim")
		}
	}
	for _, action := range a.Actions {
		if err := checkRefs(action.EvidenceIDs); err != nil {
			return err
		}
		if err := checkText(action.Action, action.EvidenceIDs, false); err != nil {
			return err
		}
		if err := checkText(action.Purpose, action.EvidenceIDs, false); err != nil {
			return err
		}
	}
	for _, risk := range a.Risks {
		if err := checkRefs(risk.EvidenceIDs); err != nil {
			return err
		}
		if err := checkText(risk.Exposure, risk.EvidenceIDs, false); err != nil {
			return err
		}
		if !strings.HasPrefix(risk.Impact, "若") && !strings.HasPrefix(risk.Impact, "一旦") {
			return fmt.Errorf("report_risk_impact_must_be_conditional")
		}
		if err := checkText(risk.Impact, risk.EvidenceIDs, true); err != nil {
			return err
		}
	}
	return nil
}
