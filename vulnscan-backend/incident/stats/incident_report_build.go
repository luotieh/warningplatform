package stats

import (
	"strings"
	"time"
	"vulnscan-backend/model"

	statsContract "vulnscan-backend/incident/stats/stats-contract"
)

func incidentWarningLevel(level int) string {
	switch level {
	case 4:
		return "一级"
	case 3:
		return "二级"
	case 2:
		return "三级"
	default:
		return "四级"
	}
}

func buildIncidentReportData(incident model.SecurityIncident, logs []model.IncidentOperationLog, vulns []model.Vulnerability) *statsContract.IncidentReportData {
	data := &statsContract.IncidentReportData{
		Title:             incident.Name,
		GeneratedAt:       time.Now(),
		IncidentNo:        incident.IncidentNo,
		Name:              incident.Name,
		Level:             model.IncidentLevelText[incident.Level],
		WarningLevel:      incidentWarningLevel(incident.Level),
		Source:            model.IncidentSourceText[incident.Source],
		Status:            model.IncidentStatusText[incident.Status],
		RiskScore:         incident.RiskScore,
		AiOpinion:         incident.AiOpinion,
		AiTags:            incident.AiTags,
		RemediationPlan:   incident.RemediationPlan,
		RemediationResult: incident.CloseReason,
		RemediationAdvice: incident.AiOpinion,
		Assignee:          incident.RemediationAssignee,
	}
	if data.RemediationAdvice == "" {
		data.RemediationAdvice = data.RemediationPlan
	}
	data.CoreConclusion = firstReportLine(incident.AiOpinion)
	data.LevelEmoji = incidentLevelEmoji(incident.Level)
	data.NotifyTargets = incidentNotifyTargets(incident.Level)
	if !incident.ReportTime.IsZero() {
		data.ReportTime = incident.ReportTime.Format("2006-01-02 15:04:05")
	}
	if incident.RemediationDeadline != nil {
		data.Deadline = incident.RemediationDeadline.Format("2006-01-02 15:04:05")
	}

	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		data.AssetName = a.AssetName
		data.SystemName = a.SystemName
		data.DomainIP = a.DomainIP
		data.SiteIP = a.SiteIP
		data.Unit = a.Unit
		data.UnitType = a.UnitType
		data.Industry = a.Industry
		data.MIITRecordNo = a.MIITRecordNo
		data.MLPSLevel = a.MLPSLevel
		data.MLPSRecordNo = a.MLPSRecordNo
		data.Region = a.Region
		data.AssetIPRange = firstNonEmpty(a.DomainIP, a.SiteIP)
		if data.AssetName == "" {
			data.AssetName = a.SystemName
		}
	}

	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		data.DataNo = m.DataNo
		data.VendorRegion = m.VendorRegion
		data.IncidentType = m.IncidentType
		data.IncidentURL = m.IncidentURL
		data.VendorName = m.VendorName
		data.AffectedCount = m.AffectedCount
		data.AffectedType = m.AffectedType
		data.CveID = m.CveId
		data.CvssScore = m.CvssScore
		if !m.DiscoveryTime.IsZero() {
			data.DiscoveryTime = m.DiscoveryTime.Format("2006-01-02 15:04:05")
		}
		if !m.VendorTime.IsZero() {
			data.VendorTime = m.VendorTime.Format("2006-01-02 15:04:05")
		}
		if strings.TrimSpace(m.IncidentDescription) != "" {
			data.Description = strings.TrimSpace(m.IncidentDescription)
			data.DescriptionSections = parseIncidentDescriptionSections(data.Description)
		}
	}
	if data.VendorName == "" {
		data.VendorName = model.IncidentSourceText[incident.Source]
	}

	for _, log := range logs {
		data.OperationLogs = append(data.OperationLogs, statsContract.IncidentReportOplog{
			Operation: log.OperationType,
			Operator:  log.OperatorName,
			Time:      log.OperationTime.Format("2006-01-02 15:04:05"),
			Comment:   log.Detail,
		})
	}

	for _, v := range vulns {
		cve := ""
		if len(v.CVEIDs) > 0 {
			cve = strings.Join(v.CVEIDs, ", ")
		}
		data.Vulnerabilities = append(data.Vulnerabilities, statsContract.IncidentReportVuln{
			Title:       v.Title,
			Severity:    v.Severity,
			CVEID:       cve,
			Asset:       v.Target,
			Status:      v.Status,
			Description: v.Description,
			Remediation: v.Solution,
		})
	}

	return data
}

func firstReportLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func incidentLevelEmoji(level int) string {
	switch level {
	case 1:
		return "🔴"
	case 2:
		return "🟠"
	case 3:
		return "🟡"
	default:
		return "🟢"
	}
}

func incidentNotifyTargets(level int) string {
	switch level {
	case 1:
		return "安全运营中心（SOC）、网络运维部、CTO办公室、合规部、业务负责人"
	case 2:
		return "安全运营中心（SOC）、网络运维部、CTO办公室、合规部"
	case 3:
		return "安全运营中心（SOC）、网络运维部"
	default:
		return "安全运营中心（SOC）"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
