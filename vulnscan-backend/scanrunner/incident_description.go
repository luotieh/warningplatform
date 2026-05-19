package scanrunner

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"
)

const (
	incidentSectionCause    = "【事件成因】"
	incidentSectionEvidence = "【证据详情】"
	incidentSectionTrace    = "【溯源信息】"
)

func buildScanIncidentCause(f model.ScanFinding, incidentType string) string {
	lines := []string{
		fmt.Sprintf("漏洞扫描发现「%s」类安全问题，严重级别：%s。", incidentType, strings.ToUpper(f.Severity)),
	}
	if strings.TrimSpace(f.Description) != "" {
		lines = append(lines, f.Description)
	}
	if f.Confidence > 0 {
		line := fmt.Sprintf("检测置信度：%d%%", f.Confidence)
		if strings.TrimSpace(f.ConfidenceReason) != "" {
			line += "（" + f.ConfidenceReason + "）"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func buildScanIncidentEvidence(f model.ScanFinding) string {
	var lines []string
	if strings.TrimSpace(f.Evidence) != "" {
		lines = append(lines, "技术证据：", f.Evidence)
	}
	if f.Data != nil {
		if svc := extractStr(f.Data, "service"); svc != "" {
			ver := extractStr(f.Data, "version")
			if ver != "" {
				lines = append(lines, fmt.Sprintf("识别服务：%s %s", svc, ver))
			} else {
				lines = append(lines, "识别服务："+svc)
			}
		}
		if banner := extractStr(f.Data, "banner"); banner != "" {
			if len(banner) > 300 {
				banner = banner[:300] + "…"
			}
			lines = append(lines, "Banner："+banner)
		}
		if poc := extractStr(f.Data, "poc_name", "template_id"); poc != "" {
			lines = append(lines, "POC/模板："+poc)
		}
	}
	if f.Port > 0 {
		proto := f.Protocol
		if proto == "" {
			proto = "tcp"
		}
		lines = append(lines, fmt.Sprintf("端口：%d/%s", f.Port, proto))
	}
	if f.VerificationLevel != "" {
		level := "原理验证"
		if f.VerificationLevel == "exploit" {
			level = "实际利用验证"
		}
		lines = append(lines, "验证级别："+level)
	}
	if strings.TrimSpace(f.VerificationDetail) != "" {
		lines = append(lines, "验证方式："+f.VerificationDetail)
	}
	if len(f.Tags) > 0 {
		lines = append(lines, "标签："+strings.Join(f.Tags, ", "))
	}
	if len(lines) == 0 {
		return "扫描引擎未返回结构化证据字段，请查看关联扫描任务与发现详情。"
	}
	return strings.Join(lines, "\n")
}

func buildScanIncidentTrace(f model.ScanFinding) string {
	lines := []string{
		"来源：漏洞扫描（自动转事件）",
		fmt.Sprintf("扫描发现 ID：%s", f.ID),
		fmt.Sprintf("扫描任务 ID：%s", f.TaskID),
	}
	if f.ModuleID != "" {
		lines = append(lines, "检测模块："+f.ModuleID)
	}
	if f.AssetID != "" {
		lines = append(lines, "关联资产 ID："+f.AssetID)
	}
	if f.Type != "" {
		lines = append(lines, "发现类型："+f.Type)
	}
	return strings.Join(lines, "\n")
}

func buildScanIncidentDescription(f model.ScanFinding, incidentType string) string {
	parts := []string{
		incidentSectionCause,
		buildScanIncidentCause(f, incidentType),
		"",
		incidentSectionEvidence,
		buildScanIncidentEvidence(f),
		"",
		incidentSectionTrace,
		buildScanIncidentTrace(f),
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}
