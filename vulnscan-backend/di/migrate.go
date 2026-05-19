package di

import (
	"encoding/json"
	"log/slog"

	"vulnscan-backend/migration"
	"vulnscan-backend/model"
	"vulnscan-backend/template/engine"

	"gorm.io/gorm"
)

func (h *Handlers) autoMigrate() {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[!] 获取数据库会话失败", "error", err)
		return
	}

	tables := []interface{}{
		&model.Asset{},
		&model.AssetGroup{},
		&model.AssetRiskHistory{},
		&model.ScanTask{},
		&model.Vulnerability{},
		&model.ScanFinding{},
		&model.ScanTemplate{},
		&model.WorkerNode{},
		&model.Node{},
		&model.ServiceFingerprint{},
		&model.WebFingerprint{},
		&model.PortServiceMap{},
		&model.Dictionary{},
		&model.DictionaryEntry{},
		&model.ScanRule{},
		&model.PocTemplate{},
		&model.FederationSyncState{},
		&model.FederationReportBuffer{},
		&model.ScanLog{},
		&model.ScanSchedule{},
		&model.VulnStatusHistory{},
		&model.Notification{},
		// 资产增强模型
		&model.Tag{},
		&model.AssetTag{},
		&model.AssetChangeLog{},
		&model.Organize{},
		&model.ConstructionOrg{},
		&model.AssetLifecycle{},
		&model.AssetCompliance{},
		&model.AssetResponsible{},
		&model.AssetRiskScore{},
		&model.Alert{},
		&model.AssetVerify{},
		&model.AssetVerifyTask{},
		&model.AssetVerifyOplog{},
		&model.AssetArchiveSnapshot{},
		&model.ComplianceTemplate{},
		&model.ComplianceTemplateItem{},
		&model.ComplianceCheckResult{},
		&model.IntegrationSource{},
		&model.IntegrationEvent{},
		&model.Workflow{},
		&model.WorkflowExecution{},
		&model.SystemSetting{},
		&model.SystemDict{},
		&model.SystemDictItem{},
		&model.DynamicFormTemplate{},
		&model.DynamicFormTemplateVersion{},
		&model.DynamicFormSubmission{},
		// 站点监控
		&model.MonitorTarget{},
		&model.MonitorPathTask{},
		&model.MonitorCrawlJob{},
		&model.MonitorDefaultConfig{},
		&model.MonitorExecution{},
		&model.MonitorAlert{},
		&model.MonitorAlertConfig{},
		&model.MonitorDispositionLog{},
		&model.MonitorAgent{},
		&model.MonitorBaseline{},
		&model.MonitorFingerprintWindow{},
		&model.MonitorWordLibrary{},
		&model.MonitorWordCategory{},
		&model.MonitorWordEntry{},
		&model.MonitorFileLibrary{},
		&model.MonitorFileEntry{},
		&model.MonitorResultSensitiveWord{},
		&model.MonitorResultSensitiveWordMatch{},
		&model.MonitorResultSensitiveFile{},
		&model.MonitorResultSensitiveFileFinding{},
		&model.MonitorRuleData{},
		&model.MonitorPerfBaseline{},
		// 威胁情报订阅 + IOC
		&model.IntelSubscription{},
		&model.IOCIndicator{},
		// ASM 攻击面管理
		&model.ASMProject{},
		&model.ASMSeed{},
		&model.ASMDiscoveredAsset{},
		&model.ASMChange{},
		&model.ASMAlertRule{},
		// Federation 同步版本管理
		&model.SyncVersion{},
		&model.SyncLog{},
	}

	if migrateErr := session.AutoMigrate(tables...); migrateErr != nil {
		slog.Error("[!] 数据库迁移失败", "error", migrateErr)
	} else {
		slog.Info("[+] 数据库迁移完成", "tables", len(tables))
	}

	// 目标/路径任务重构后，GORM 不会自动删除 monitor_executions.task_id
	if session.Migrator().HasTable("monitor_executions") && session.Migrator().HasColumn("monitor_executions", "task_id") {
		if err := session.Migrator().DropColumn("monitor_executions", "task_id"); err != nil {
			slog.Warn("[!] 移除 monitor_executions.task_id 失败", "error", err)
		} else {
			slog.Info("[+] 已移除 monitor_executions.task_id 遗留列")
		}
	}

	if err := migration.RunAll(session); err != nil {
		slog.Error("[!] 数据迁移脚本执行失败", "error", err)
	}

	reconCategories := []string{
		"host_alive", "port_open", "udp_port", "service",
		"web_page", "dns_record", "subdomain", "cert_info",
		"favicon", "tech", "api", "waf", "js_info", "crawler",
	}
	result := session.Where("category IN ?", reconCategories).Delete(&model.Vulnerability{})
	if result.RowsAffected > 0 {
		slog.Info("[+] 已清理信息收集类误入漏洞表的记录", "count", result.RowsAffected)
	}
}

func (h *Handlers) seedBuiltinTemplates(session *gorm.DB) {
	builtins := engine.BuiltinTemplates()
	for _, bt := range builtins {
		var count int64
		session.Model(&model.ScanTemplate{}).Where("id = ? OR code = ?", bt.ID, bt.ID).Count(&count)
		if count > 0 {
			content, _ := json.Marshal(bt)
			session.Model(&model.ScanTemplate{}).Where("id = ? OR code = ?", bt.ID, bt.ID).
				Updates(map[string]interface{}{
					"content": string(content),
					"version": bt.Version,
					"name":    bt.Name,
				})
			continue
		}
		content, _ := json.Marshal(bt)
		item := model.ScanTemplate{
			ID:          bt.ID,
			Name:        bt.Name,
			Code:        bt.ID,
			Category:    "builtin",
			Description: bt.Description,
			Tags:        model.StringArray(bt.Tags),
			Content:     string(content),
			Version:     bt.Version,
			Builtin:     true,
			Enabled:     true,
			AuthorID:    "system",
		}
		session.Create(&item)
	}
}
