package model

// ─── 事件等级 ───

const (
	IncidentLevelLow    = 1
	IncidentLevelMedium = 2
	IncidentLevelHigh   = 3
	IncidentLevelUrgent = 4
)

var IncidentLevelText = map[int]string{
	IncidentLevelLow:    "低危",
	IncidentLevelMedium: "中危",
	IncidentLevelHigh:   "高危",
	IncidentLevelUrgent: "紧急",
}

// ─── 事件来源 ───

const (
	IncidentSourceSiteMonitor = 1
	IncidentSourceVulnScan    = 2
	IncidentSourceTraffic     = 3
	IncidentSourceRiskProbe   = 4
)

var IncidentSourceText = map[int]string{
	IncidentSourceSiteMonitor: "站点监测",
	IncidentSourceVulnScan:    "漏洞扫描",
	IncidentSourceTraffic:     "流量分析",
	IncidentSourceRiskProbe:   "风险探测",
}

// ─── 事件状态 ───

const (
	IncidentStatusPendingReview = 1
	IncidentStatusReviewPassed  = 2
	IncidentStatusReviewFailed  = 3
	IncidentStatusRemediation   = 4
	IncidentStatusRemediating   = 5
	IncidentStatusVerifying     = 6
	IncidentStatusClosed        = 7
)

var IncidentStatusText = map[int]string{
	IncidentStatusPendingReview: "待人工复核",
	IncidentStatusReviewPassed:  "复核通过",
	IncidentStatusReviewFailed:  "复核失败",
	IncidentStatusRemediation:   "待整改",
	IncidentStatusRemediating:   "整改中",
	IncidentStatusVerifying:     "待验证",
	IncidentStatusClosed:        "已关闭",
}

// ─── AI 预审状态 ───

const (
	IncidentAiPreStatusNone = 0
	IncidentAiPreStatusDone = 1
)

// ─── SLA 等级 ───

const (
	IncidentSLALevelNone     = 0
	IncidentSLALevelStandard = 1 // 24h
	IncidentSLALevelUrgent   = 2 // 8h
	IncidentSLALevelCritical = 3 // 4h
)

var IncidentSLALevelText = map[int]string{
	IncidentSLALevelNone:     "无",
	IncidentSLALevelStandard: "标准(24h)",
	IncidentSLALevelUrgent:   "紧急(8h)",
	IncidentSLALevelCritical: "特急(4h)",
}

// ─── SLA 状态 ───

const (
	IncidentSLAStatusNormal    = 0
	IncidentSLAStatusWarning   = 1
	IncidentSLAStatusBreached  = 2
	IncidentSLAStatusEscalated = 3
)

var IncidentSLAStatusText = map[int]string{
	IncidentSLAStatusNormal:    "正常",
	IncidentSLAStatusWarning:   "即将超期",
	IncidentSLAStatusBreached:  "已超期",
	IncidentSLAStatusEscalated: "已升级",
}

func IncidentSLAHours(level int) int {
	switch level {
	case IncidentSLALevelStandard:
		return 24
	case IncidentSLALevelUrgent:
		return 8
	case IncidentSLALevelCritical:
		return 4
	default:
		return 0
	}
}

func IncidentAutoSLALevel(level int) int {
	switch level {
	case IncidentLevelUrgent:
		return IncidentSLALevelCritical
	case IncidentLevelHigh:
		return IncidentSLALevelUrgent
	default:
		return IncidentSLALevelStandard
	}
}

func IncidentCurrentStep(status int, aiPreStatus int) int {
	switch status {
	case IncidentStatusPendingReview:
		return 1
	case IncidentStatusReviewFailed:
		return 2
	case IncidentStatusReviewPassed, IncidentStatusRemediation:
		return 3
	case IncidentStatusRemediating:
		return 4
	case IncidentStatusVerifying:
		return 5
	case IncidentStatusClosed:
		return 6
	default:
		return 1
	}
}

// ─── 事件操作类型 ───

const (
	IncidentOpInput        = "input"
	IncidentOpAIPreAudit   = "ai_pre_audit"
	IncidentOpManualReview = "manual_review"
	IncidentOpTransfer     = "transfer"
	IncidentOpDistribute   = "distribute"
	IncidentOpArchive      = "archive"
	IncidentOpRemediation  = "remediation"
	IncidentOpVerify       = "verify"
	IncidentOpClose        = "close"
	IncidentOpBatchImport  = "batch_import"
)

var IncidentOperationTypeText = map[string]string{
	IncidentOpInput:        "录入",
	IncidentOpAIPreAudit:   "AI预审",
	IncidentOpManualReview: "人工复核",
	IncidentOpTransfer:     "流转到通报",
	IncidentOpDistribute:   "通报下发",
	IncidentOpArchive:      "归档",
	IncidentOpRemediation:  "提交整改",
	IncidentOpVerify:       "验证整改",
	IncidentOpClose:        "关闭",
	IncidentOpBatchImport:  "批量导入",
}

const (
	IncidentSourceSystemLocal    = "security-incident"
	IncidentSourceSystemCircular = "circular"
)

// ─── 事件派发状态 ───

const (
	IncidentDispatchStatusPending   = 1
	IncidentDispatchStatusSent      = 2
	IncidentDispatchStatusConfirmed = 3
	IncidentDispatchStatusFailed    = 4
)

var IncidentDispatchStatusText = map[int]string{
	IncidentDispatchStatusPending:   "待下发",
	IncidentDispatchStatusSent:      "已下发",
	IncidentDispatchStatusConfirmed: "已确认回执",
	IncidentDispatchStatusFailed:    "下发失败",
}
