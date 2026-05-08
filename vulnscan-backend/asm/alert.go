package asm

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type AlertEngine struct {
	db *gorm.DB
}

func NewAlertEngine(db *gorm.DB) *AlertEngine {
	return &AlertEngine{db: db}
}

func (e *AlertEngine) EvaluateRules(projectID string, changes []AssetChange, assets []DiscoveredAsset) int {
	var rules []model.ASMAlertRule
	e.db.Where("project_id = ? AND enabled = ?", projectID, true).Find(&rules)
	if len(rules) == 0 {
		return 0
	}

	triggered := 0
	for _, rule := range rules {
		matched := e.evaluateRule(rule, changes, assets)
		if matched {
			e.fireAlert(rule, projectID)
			triggered++
		}
	}

	if triggered > 0 {
		slog.Info("[!] ASM 告警规则触发", "project", projectID, "triggered", triggered)
	}
	return triggered
}

func (e *AlertEngine) evaluateRule(rule model.ASMAlertRule, changes []AssetChange, assets []DiscoveredAsset) bool {
	ruleType, _ := rule.Condition["type"].(string)

	switch ruleType {
	case "new_asset":
		return e.matchNewAsset(rule, changes)
	case "asset_removed":
		return e.matchRemovedAsset(rule, changes)
	case "high_risk":
		return e.matchHighRisk(rule, assets)
	case "port_change":
		return e.matchPortChange(rule, changes)
	case "cert_change":
		return e.matchCertChange(rule, changes)
	case "count_threshold":
		return e.matchCountThreshold(rule, assets)
	default:
		return false
	}
}

func (e *AlertEngine) matchNewAsset(rule model.ASMAlertRule, changes []AssetChange) bool {
	assetType, _ := rule.Condition["asset_type"].(string)
	for _, ch := range changes {
		if ch.Field == "status" && ch.NewValue == "new" {
			if assetType == "" {
				return true
			}
		}
	}
	if assetType != "" {
		for _, ch := range changes {
			if ch.Field == "status" && ch.NewValue == "new" {
				return true
			}
		}
	}
	return false
}

func (e *AlertEngine) matchRemovedAsset(_ model.ASMAlertRule, changes []AssetChange) bool {
	for _, ch := range changes {
		if ch.Field == "status" && ch.NewValue == "removed" {
			return true
		}
	}
	return false
}

func (e *AlertEngine) matchHighRisk(rule model.ASMAlertRule, assets []DiscoveredAsset) bool {
	thresholdStr, _ := rule.Condition["threshold"].(string)
	threshold, _ := strconv.Atoi(thresholdStr)
	if threshold == 0 {
		threshold = 70
	}
	for _, a := range assets {
		if a.RiskScore >= threshold {
			return true
		}
	}
	return false
}

func (e *AlertEngine) matchPortChange(_ model.ASMAlertRule, changes []AssetChange) bool {
	for _, ch := range changes {
		if strings.HasPrefix(ch.Field, "attr.port") || strings.HasPrefix(ch.Field, "attr.open_ports") {
			return true
		}
	}
	return false
}

func (e *AlertEngine) matchCertChange(_ model.ASMAlertRule, changes []AssetChange) bool {
	for _, ch := range changes {
		if strings.Contains(ch.Field, "cert") || strings.Contains(ch.Field, "tls") || strings.Contains(ch.Field, "issuer") {
			return true
		}
	}
	return false
}

func (e *AlertEngine) matchCountThreshold(rule model.ASMAlertRule, assets []DiscoveredAsset) bool {
	maxStr, _ := rule.Condition["max_count"].(string)
	maxCount, _ := strconv.Atoi(maxStr)
	if maxCount == 0 {
		return false
	}
	return len(assets) > maxCount
}

func (e *AlertEngine) fireAlert(rule model.ASMAlertRule, projectID string) {
	alert := model.Alert{
		ID:          fmt.Sprintf("asma_%d", time.Now().UnixNano()),
		AlertType:   "asm_rule",
		Severity:    model.SeverityLevel(e.ruleSeverity(rule)),
		Title:       fmt.Sprintf("[ASM] %s", rule.Name),
		Description: fmt.Sprintf("攻击面管理规则 [%s] 已触发 (项目: %s)", rule.Name, projectID),
		Source:      "asm",
		Status:      model.AlertOpen,
	}

	if err := e.db.Create(&alert).Error; err != nil {
		slog.Error("ASM 告警创建失败", "rule", rule.Name, "error", err)
	}
}

func (e *AlertEngine) ruleSeverity(rule model.ASMAlertRule) string {
	if s, ok := rule.Condition["severity"].(string); ok && s != "" {
		return s
	}
	switch rule.Type {
	case "new_asset":
		return "medium"
	case "high_risk":
		return "high"
	case "port_change", "cert_change":
		return "medium"
	default:
		return "low"
	}
}
