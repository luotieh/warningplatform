package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// OfflineReportRequest exposes the production final-report projection only.
// It never loads a Store or executes F, S or C. Context is explanatory and
// deliberately cannot replace the frozen ReportEvidenceBundle.
type OfflineReportRequest struct {
	PromptVersion string          `json:"prompt_version"`
	System        string          `json:"system"`
	User          json.RawMessage `json:"user"`
}

const offlineReportBoundary = "本次是四份合成事件的离线验收。assessment_context全部为有来源的合成背景，独立验证状态为false；只辅助解释，不参与F/S/C计分。S来自受控Stub，绝非本次K2.7独立核验，C05/C06的模拟语义支持仅在受控情景下成立。IOC标签来自Synthetic Threat Intel，不能称真实情报查询或确认恶意。策略分不是恶意概率，零策略分也不能机械解释为无风险。业务替代解释仅为待核查假设，放gaps和核查动作，不写成已证事实。不能声称感染、账号失陷、真实凭据泄露、利用成功、持久化控制或外传已发生。报告时间统一使用北京时间（UTC+08:00）；输入中的Z时间须转换后注明时区。正文以正式结构化ReportAssessment返回，interpretations为空；事实论证只引用key_evidence中的F/S/I编号，其他ID用于本地追溯。研判结论须说明证据强度和待核实边界，supporting组织真正同主体关联的证据链，opposing只能引用完整有效阴性，risks和actions给出针对本资产、时间范围、连接/日志/进程的调查与条件性处置。gaps必须写明合成数据、Stub、合成IOC、未证明后果及未校准概率。不要把assessment_context中的模拟设定升级为实际通信或主机证据。"

func PrepareOfflineReport(event domain.Event, frozen PreparedEvidenceExecution, context json.RawMessage) (OfflineReportRequest, error) {
	if frozen.Evidence.Pipeline == nil || frozen.Evidence.PhaseOne == nil || frozen.Contract == nil {
		return OfflineReportRequest{}, fmt.Errorf("offline_requires_frozen_pipeline_contract")
	}
	if frozen.Contract.EventID != event.EventID {
		return OfflineReportRequest{}, fmt.Errorf("offline_event_mismatch")
	}
	prompt, err := evidenceReportPrompt(event, frozen, frozen.Evidence, "")
	if err != nil {
		return OfflineReportRequest{}, err
	}
	var input map[string]any
	if err = json.Unmarshal([]byte(prompt), &input); err != nil {
		return OfflineReportRequest{}, err
	}
	var ctx map[string]any
	if err = json.Unmarshal(context, &ctx); err != nil {
		return OfflineReportRequest{}, err
	}
	if ctx["event_id"] != event.EventID {
		return OfflineReportRequest{}, fmt.Errorf("offline_context_event_mismatch")
	}
	input["assessment_context"] = ctx
	input["evidence_boundaries"] = offlineReportBoundary
	input["evidence_facts_origin"] = "immutable F/S/C and normalization; S controlled Stub, not independently verified semantics"
	// Retain the formal bounded selection for claims. These small ledgers make
	// omitted gaps/negatives explicit without shipping all raw 82-rule audits.
	gaps := map[string][]string{}
	negatives := []map[string]any{}
	refs := map[string]any{}
	for _, item := range frozen.Evidence.Normalized.Items {
		if item.TerminalStatus == "missing" {
			gaps[item.RuleID] = uniqueSortedStrings(append(gaps[item.RuleID], item.Reason))
		}
		if item.Kind == "fact" && item.ExecutionStatus == "executed" && item.TerminalStatus == "not_observed" && item.Quality == "complete" {
			negatives = append(negatives, map[string]any{"id": item.ID, "report_id": item.ReportID, "rule_id": item.RuleID, "scope": item.Scope, "window": item.Window, "status": item.TerminalStatus, "reason": item.Reason})
		}
		if item.ReportID != "" {
			refs[item.ReportID] = map[string]any{"normalized_id": item.ID, "rule_id": item.RuleID, "source_set": frozen.Contract.SourceIndex[item.ID], "source_count": len(item.SourceIDs)}
		}
	}
	input["missing_evidence"] = gaps
	input["negative_evidence"] = negatives
	input["source_references"] = refs
	input["source_reference_note"] = "source_set resolves to immutable local contract.source_sets; only key_evidence IDs may authorize report claims; an omitted negative is not automatically authorized as opposing"
	raw, err := json.Marshal(input)
	system := evidenceReportSystemPrompt + "\n离线合成验收补充约束（报告使用北京时间）：" + offlineReportBoundary
	if len(raw) > 100000 || estimateTokens(string(raw)) > reportInputEstimateBudget || estimateTokens(system+string(raw))+12 > reportPromptEstimateBudget {
		return OfflineReportRequest{}, fmt.Errorf("offline_report_input_budget_exceeded")
	}
	return OfflineReportRequest{PromptVersion: "production-report-2.0/offline-context-1", System: system, User: raw}, err
}

// ValidateOfflineReport retains the production reference, numeric, negative and
// success-boundary validators. Explicit provenance checks are additional gates,
// not a claim that natural-language factual accuracy is exhaustively decidable.
func ValidateOfflineReport(raw string, event domain.Event, frozen PreparedEvidenceExecution, model string) (ReportDocument, error) {
	a, err := decodeReportAssessment(raw, frozen.Evidence)
	if err != nil {
		return ReportDocument{}, err
	}
	var response map[string]json.RawMessage
	if err = json.Unmarshal([]byte(raw), &response); err != nil {
		return ReportDocument{}, err
	}
	if risk, ok := response["evidence_risk"]; ok && string(risk) != "null" {
		var proposed struct {
			Score *int `json:"score"`
		}
		if json.Unmarshal(risk, &proposed) != nil || proposed.Score == nil || *proposed.Score != frozen.Evidence.PhaseOne.Result.Score {
			return ReportDocument{}, fmt.Errorf("offline_model_cannot_change_policy_score")
		}
	}
	text := strings.Join(a.Gaps, "；")
	for _, term := range []string{"合成", "Stub", "IOC"} {
		if !strings.Contains(text, term) {
			return ReportDocument{}, fmt.Errorf("offline_provenance_disclosure_missing:%s", term)
		}
	}
	for _, term := range []string{"VirusTotal已确认", "OTX已确认", "微步已确认", "K2.7已独立确认", "K2.7已验证恶意语义"} {
		if strings.Contains(raw, term) {
			return ReportDocument{}, fmt.Errorf("offline_synthetic_provenance_overclaim")
		}
	}
	doc := ReportDocument{SchemaVersion: reportEvidenceVersion, LayoutVersion: reportFivePartLayout,
		EventID: event.EventID, Title: event.EventName, CreatedAt: time.Now().UTC(), Kind: "offline-synthetic-assessment",
		Evidence: frozen.Evidence, Assessment: a, Validation: pipelineReportValidation,
		ModelIdentity: model, AssetSection: frozen.AssetSection}
	doc.Markdown = "# " + reportCell(doc.Title) + "\n\n> 合成数据验收：S为受控Stub，IOC为合成情报；策略分不是恶意概率，未证明感染、账号失陷、利用成功或外传。\n\n" + renderReportMarkdown(doc)
	return doc, nil
}

// RenderOfflineReportDocument fills the production renderer from the original
// snapshot, whose event metadata is not retained in the compressed execution
// Context. It never modifies the frozen evidence or recomputes an overview.
func RenderOfflineReportDocument(doc ReportDocument, bundle PreparedEvidenceBundle) ReportDocument {
	raw, _ := json.Marshal(bundle.Snapshot.Context)
	assets, _ := json.Marshal(bundle.Assets)
	doc.AssetSection = string(assets)
	doc.EventOverview = reportEventOverview(bundle.Event, string(raw), doc.AssetSection)
	doc.Markdown = "# " + reportCell(doc.Title) + "\n\n> 合成数据验收：S为受控Stub，IOC为合成情报；策略分不是恶意概率，未证明感染、账号失陷、利用成功或外传。\n\n" + renderReportMarkdown(doc)
	return doc
}
