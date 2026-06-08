package scanrunner

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

func vulnFingerprint(taskID, target string, port int, title, moduleID, templateID string) string {
	raw := fmt.Sprintf("%s|%s|%d|%s|%s|%s", taskID, strings.ToLower(strings.TrimSpace(target)), port,
		strings.ToLower(strings.TrimSpace(title)), moduleID, templateID)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:12])
}

// SyncVulnerabilitiesFromTask 将扫描任务中的漏洞类发现同步到 vs_vulnerability。
func SyncVulnerabilitiesFromTask(db *gorm.DB, task *model.ScanTask) (int, error) {
	if db == nil || task == nil {
		return 0, nil
	}
	if task.Type == model.TaskTypeAssetEnrich || task.Type == model.TaskTypeAssetDiscovery || task.Type == model.TaskTypeVulnRetest {
		return 0, nil
	}

	var findings []model.ScanFinding
	if err := db.Where("task_id = ? AND category = ?", task.ID, model.FindingCategoryVuln).Find(&findings).Error; err != nil {
		return 0, err
	}

	slog.Info("[SyncVuln] 查询漏洞类发现",
		"task_id", task.ID,
		"category", model.FindingCategoryVuln,
		"found_count", len(findings),
	)

	if len(findings) == 0 {
		return 0, nil
	}

	now := time.Now()
	synced := 0

	// Pre-load PoC template ProductIDs for batch resolution
	pocProductCache := make(map[string]string)

	for i := range findings {
		f := findings[i]
		tplID := ""
		if f.Data != nil {
			if v, ok := f.Data["template_id"].(string); ok {
				tplID = v
			}
			if tplID == "" {
				if v, ok := f.Data["poc_id"].(string); ok {
					tplID = v
				}
			}
		}
		fp := vulnFingerprint(task.ID, f.Target, f.Port, f.Title, f.ModuleID, tplID)

		productID := resolveVulnProductID(db, f, tplID, pocProductCache)

		var existing model.Vulnerability
		err := db.Where("task_id = ? AND target = ? AND port = ? AND title = ? AND module_id = ?",
			task.ID, f.Target, f.Port, f.Title, f.ModuleID).First(&existing).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			continue
		}

		if err == gorm.ErrRecordNotFound {
			solution := ""
			var cweIDs model.StringArray
			if f.Data != nil {
				if r, ok := f.Data["remediation"].(string); ok {
					solution = r
				}
				if c, ok := f.Data["cwe_ids"].(string); ok && c != "" {
					cweIDs = strings.Split(c, ",")
				}
			}
			v := model.Vulnerability{
				ID:          ulid.GenerateID(),
				TaskID:      task.ID,
				AssetID:     f.AssetID,
				Target:      f.Target,
				Port:        f.Port,
				Protocol:    f.Protocol,
				Title:       f.Title,
				Description: f.Description,
				Solution:    solution,
				Severity:    f.Severity,
				CWEIDs:      cweIDs,
				ModuleID:    f.ModuleID,
				TemplateID:  tplID,
				ProductID:   productID,
				Evidence:    f.Evidence,
				Status:      model.VulnStatusOpen,
				Confidence:  f.Confidence,
				CreatedBy:   task.CreatedBy,
				OrganizeID:  task.OrganizeID,
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if v.Severity == "" {
				v.Severity = "info"
			}
			if err := db.Create(&v).Error; err == nil {
				synced++
				_ = fp
			}
			continue
		}

		updates := map[string]any{
			"asset_id":    f.AssetID,
			"description": f.Description,
			"severity":    f.Severity,
			"evidence":    f.Evidence,
			"confidence":  f.Confidence,
			"template_id": tplID,
			"updated_at":  now,
		}
		if productID != "" {
			updates["product_id"] = productID
		}
		if err := db.Model(&model.Vulnerability{}).Where("id = ?", existing.ID).Updates(updates).Error; err == nil {
			synced++
		}
	}
	return synced, nil
}

// resolveVulnProductID tries to find a ProductID from the PoC template or finding data.
func resolveVulnProductID(db *gorm.DB, f model.ScanFinding, tplID string, cache map[string]string) string {
	if tplID != "" {
		if pid, ok := cache[tplID]; ok {
			return pid
		}
		var pocRec model.PocTemplate
		err := db.Select("product_id").Where("poc_id = ? OR id = ?", tplID, tplID).First(&pocRec).Error
		if err == nil && pocRec.ProductID != "" {
			cache[tplID] = pocRec.ProductID
			return pocRec.ProductID
		}
		cache[tplID] = ""
	}

	if f.Data != nil {
		if product, ok := f.Data["product"].(string); ok && product != "" {
			var prod model.Product
			if err := db.Where("name = ?", strings.ToLower(strings.TrimSpace(product))).
				Select("id").First(&prod).Error; err == nil {
				return prod.ID
			}
		}
	}
	return ""
}

// EnsureVulnFromFinding 将单条扫描发现写入漏洞库并返回漏洞 ID。
func EnsureVulnFromFinding(db *gorm.DB, findingID string) (string, error) {
	var f model.ScanFinding
	if err := db.First(&f, "id = ?", findingID).Error; err != nil {
		return "", err
	}
	if f.Category != model.FindingCategoryVuln {
		return "", fmt.Errorf("非漏洞类发现，无法回测")
	}
	var task model.ScanTask
	if err := db.First(&task, "id = ?", f.TaskID).Error; err != nil {
		return "", err
	}

	tplID := ""
	if f.Data != nil {
		if v, ok := f.Data["template_id"].(string); ok {
			tplID = v
		}
	}

	var existing model.Vulnerability
	err := db.Where("task_id = ? AND target = ? AND port = ? AND title = ? AND module_id = ?",
		f.TaskID, f.Target, f.Port, f.Title, f.ModuleID).First(&existing).Error
	if err == nil {
		return existing.ID, nil
	}
	if err != gorm.ErrRecordNotFound {
		return "", err
	}

	now := time.Now()
	sev := f.Severity
	if sev == "" {
		sev = "info"
	}
	productID := resolveVulnProductID(db, f, tplID, map[string]string{})
	v := model.Vulnerability{
		ID:          ulid.GenerateID(),
		TaskID:      f.TaskID,
		AssetID:     f.AssetID,
		Target:      f.Target,
		Port:        f.Port,
		Protocol:    f.Protocol,
		Title:       f.Title,
		Description: f.Description,
		Severity:    sev,
		ModuleID:    f.ModuleID,
		TemplateID:  tplID,
		ProductID:   productID,
		Evidence:    f.Evidence,
		Status:      model.VulnStatusOpen,
		Confidence:  f.Confidence,
		CreatedBy:   task.CreatedBy,
		OrganizeID:  task.OrganizeID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.Create(&v).Error; err != nil {
		return "", err
	}
	return v.ID, nil
}
