package scanrunner

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"

	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

var reconFindingTypes = map[string]struct{}{
	"host_alive":       {},
	"port_open":        {},
	"udp_port":         {},
	"service":          {},
	"web_page":         {},
	"web_info":         {},
	"dns_record":       {},
	"subdomain":        {},
	"cert_info":        {},
	"favicon":          {},
	"tech":             {},
	"api":              {},
	"waf":              {},
	"js_info":          {},
	"crawler":          {},
	"url":              {},
	"form":             {},
	"xhr":              {},
	"cdn_detected":     {},
	"zone_transfer":    {},
	"internal_ip_leak": {},
	"fingerprint":      {},
	"real_ip":          {},
	"email":            {},
}

func isReconFinding(f *core.Finding) bool {
	_, ok := reconFindingTypes[f.Type]
	return ok
}

func (r *Runner) persistFindings() {
	findings := r.progress.GetFindings()

	if len(findings) == 0 {
		return
	}

	assetCache := r.buildAssetCache()

	seen := make(map[string]struct{})
	var records []model.ScanFinding
	reconCount, vulnCount := 0, 0

	for _, f := range findings {
		dedupKey := computeDedupKey(r.task.ID, f)
		if _, ok := seen[dedupKey]; ok {
			continue
		}
		seen[dedupKey] = struct{}{}

		rec := findingToRecord(r.task, f)
		rec.AssetID = r.resolveAssetID(assetCache, rec.Target, rec.Port)
		records = append(records, rec)

		if rec.Category == model.FindingCategoryRecon {
			reconCount++
		} else {
			vulnCount++
		}
	}

	if len(records) == 0 {
		return
	}

	created := r.batchPersistFindings(records)

	slog.Info("[Persist] 扫描发现已持久化",
		"task_id", r.task.ID,
		"total", len(records),
		"recon", reconCount,
		"vuln", vulnCount,
		"created", created,
	)
}

func (r *Runner) buildAssetCache() map[string]string {
	cache := make(map[string]string)
	var assets []model.Asset
	if err := r.db.Select("id, address, ipv4, domain, port").Find(&assets).Error; err != nil {
		return cache
	}
	for _, a := range assets {
		if a.Address != "" {
			cache[fmt.Sprintf("%s:%d", a.Address, a.Port)] = a.ID
			cache[a.Address] = a.ID
		}
		if a.IPv4 != "" {
			cache[a.IPv4] = a.ID
		}
		if a.Domain != "" {
			cache[a.Domain] = a.ID
		}
	}
	return cache
}

func (r *Runner) resolveAssetID(cache map[string]string, target string, port int) string {
	if target == "" {
		return ""
	}
	if port > 0 {
		if id, ok := cache[fmt.Sprintf("%s:%d", target, port)]; ok {
			return id
		}
	}
	if id, ok := cache[target]; ok {
		return id
	}
	return ""
}

func findingToRecord(task model.ScanTask, f *core.Finding) model.ScanFinding {
	target := ""
	port := 0
	protocol := ""
	if f.Target != nil {
		target = f.Target.Host
		if target == "" && f.Target.IP != "" {
			target = f.Target.IP
		}
		if target == "" && f.Target.URL != "" {
			target = extractHostFromURL(f.Target.URL)
		}
		port = f.Target.Port
		protocol = f.Target.Protocol
	}

	severity := f.Severity
	if severity == "" {
		severity = "info"
	}

	category := model.FindingCategoryVuln
	if isReconFinding(f) {
		category = model.FindingCategoryRecon
	}

	data := model.JSONMap{}
	for k, v := range f.Data {
		data[k] = v
	}

	verificationLevel := string(f.VerificationLevel)
	if verificationLevel == "" {
		verificationLevel = "principle"
	}

	return model.ScanFinding{
		ID:                 qulid.GenerateID(),
		TaskID:             task.ID,
		ModuleID:           f.ModuleID,
		Type:               f.Type,
		Category:           category,
		Target:             target,
		Port:               port,
		Protocol:           protocol,
		Title:              f.Title,
		Description:        f.Description,
		Severity:           severity,
		Confidence:         f.Confidence,
		ConfidenceReason:   f.ConfidenceReason,
		Evidence:           f.Evidence,
		VerificationLevel:  verificationLevel,
		VerificationDetail: f.VerificationDetail,
		Data:               data,
		CreatedAt:          time.Now(),
	}
}

func extractHostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	if host != "" {
		return host
	}
	return rawURL
}

func computeDedupKey(taskID string, f *core.Finding) string {
	target := ""
	port := 0
	protocol := ""
	if f.Target != nil {
		target = f.Target.Host + f.Target.IP + f.Target.URL
		port = f.Target.Port
		protocol = f.Target.Protocol
	}
	raw := fmt.Sprintf("%s|%s|%d|%s|%s|%s", taskID, target, port, protocol, f.ModuleID, f.Title)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:16])
}
