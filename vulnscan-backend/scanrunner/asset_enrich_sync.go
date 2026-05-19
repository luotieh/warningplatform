package scanrunner

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/assethost"
)

// SyncAssetTableAfterEnrichScan 在「资产信息富化」类扫描成功结束后，将发现摘要回写到 vs_asset。
// 仅按 finding.asset_id 或任务 parameters 中的资产绑定汇总，不按域名匹配资产表。
func SyncAssetTableAfterEnrichScan(db *gorm.DB, task *model.ScanTask) error {
	if db == nil || task == nil {
		return nil
	}
	if task.Type != model.TaskTypeAssetEnrich {
		return nil
	}

	var findings []model.ScanFinding
	if err := db.Where("task_id = ?", task.ID).Find(&findings).Error; err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}

	resolver := BuildAssetIDResolver(task)
	byAsset := map[string][]model.ScanFinding{}
	for i := range findings {
		f := findings[i]
		aid := strings.TrimSpace(f.AssetID)
		if aid == "" {
			aid = resolver.Resolve(f.Target, f.Port)
		}
		if aid == "" {
			continue
		}
		byAsset[aid] = append(byAsset[aid], f)
	}

	now := time.Now()
	for aid, fs := range byAsset {
		var asset model.Asset
		if err := db.First(&asset, "id = ?", aid).Error; err != nil {
			continue
		}
		updates := buildAssetUpdatesFromEnrichFindings(fs, &asset)
		if len(updates) == 0 {
			db.Model(&model.Asset{}).Where("id = ?", aid).Update("last_scan_at", now)
			continue
		}
		updates["last_scan_at"] = now
		if err := db.Model(&model.Asset{}).Where("id = ?", aid).Updates(updates).Error; err != nil {
			slog.Warn("[AssetEnrichSync] 回写资产失败", "asset_id", aid, "task_id", task.ID, "error", err)
			continue
		}
		slog.Info("[AssetEnrichSync] 已回写资产表", "asset_id", aid, "task_id", task.ID, "fields", len(updates))
	}
	return nil
}

func stringFromJSONMap(m model.JSONMap, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	switch s := v.(type) {
	case string:
		return strings.TrimSpace(s), true
	default:
		return strings.TrimSpace(fmt.Sprint(s)), true
	}
}

func stringSliceFromJSONMap(m model.JSONMap, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		var out []string
		for _, it := range s {
			if it == nil {
				continue
			}
			if str, ok := it.(string); ok {
				out = append(out, str)
			} else {
				out = append(out, fmt.Sprint(it))
			}
		}
		return out
	default:
		return nil
	}
}

func buildAssetUpdatesFromEnrichFindings(fs []model.ScanFinding, asset *model.Asset) map[string]interface{} {
	updates := make(map[string]interface{})
	if asset == nil {
		return updates
	}

	var ipv4 string
	var ptrDomain string
	var sslExpiry *time.Time
	var cand *svcPick

	for i := range fs {
		f := fs[i]
		switch f.ModuleID {
		case "dns_all":
			if rt, ok := dataStr(f.Data, "record_type"); ok && strings.EqualFold(rt, "A") {
				if val, ok := dataStr(f.Data, "value"); ok {
					if ip := net.ParseIP(strings.TrimSpace(val)); ip != nil {
						if v4 := ip.To4(); v4 != nil && ipv4 == "" {
							ipv4 = v4.String()
						}
					}
				}
			}
			if rt, ok := dataStr(f.Data, "record_type"); ok && strings.EqualFold(rt, "PTR") {
				if val, ok := dataStr(f.Data, "value"); ok && ptrDomain == "" {
					ptrDomain = sanitizePTRHost(val)
				}
			}
		case "ip_attr":
			if ip, ok := dataStr(f.Data, "ip"); ok && net.ParseIP(ip) != nil && ipv4 == "" {
				ipv4 = strings.TrimSpace(ip)
			}
			if ph, ok := dataStr(f.Data, "ptr_host"); ok && ptrDomain == "" {
				ptrDomain = sanitizePTRHost(ph)
			}
		case "cert_check":
			if t, ok := certExpiryFromFinding(&f); ok {
				sslExpiry = earliest(sslExpiry, t)
			}
		case "service_probe":
			if t, ok := certExpiryFromFinding(&f); ok {
				sslExpiry = earliest(sslExpiry, t)
			}
			if f.Type == "service" && asset.Port == 0 {
				p := pickService(&f)
				if p != nil && (cand == nil || p.rank() > cand.rank()) {
					cand = p
				}
			}
		}
	}

	if ipv4 != "" {
		updates["ipv4"] = ipv4
	}
	if ptrDomain != "" && assethost.ShouldApplyPTRDomain(asset.Address, asset.URL, asset.Domain, asset.Name, ptrDomain) {
		updates["domain"] = assethost.ExtractHost(ptrDomain)
	}
	if sslExpiry != nil {
		updates["ssl_expires_at"] = *sslExpiry
	}
	if cand != nil && asset.Port == 0 {
		updates["port"] = cand.port
		if cand.protocol != "" {
			updates["protocol"] = cand.protocol
		}
		if cand.service != "" {
			updates["service"] = cand.service
		}
		if cand.version != "" {
			updates["version"] = cand.version
		}
	}
	return updates
}

func sanitizePTRHost(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "amazonaws") || strings.Contains(lower, "cloudflare") ||
		strings.Contains(lower, "akamai") || strings.Contains(lower, "cdn") {
		return ""
	}
	return s
}

func dataStr(data model.JSONMap, key string) (string, bool) {
	if data == nil {
		return "", false
	}
	v, ok := data[key]
	if !ok || v == nil {
		return "", false
	}
	switch s := v.(type) {
	case string:
		return strings.TrimSpace(s), true
	default:
		return strings.TrimSpace(fmt.Sprint(s)), true
	}
}

func certExpiryFromFinding(f *model.ScanFinding) (time.Time, bool) {
	if f.Data == nil {
		return time.Time{}, false
	}
	for _, key := range []string{"expires_at", "expired_at", "tls_not_after"} {
		s, ok := dataStr(f.Data, key)
		if !ok || s == "" {
			continue
		}
		layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func earliest(cur *time.Time, t time.Time) *time.Time {
	if cur == nil {
		return &t
	}
	if t.Before(*cur) {
		cp := t
		return &cp
	}
	return cur
}

type svcPick struct {
	port     int
	protocol string
	service  string
	version  string
	conf     int
}

func (p *svcPick) rank() int {
	score := p.conf + p.port
	switch p.port {
	case 443:
		score += 5000
	case 8443:
		score += 4000
	case 80:
		score += 3000
	}
	if strings.Contains(strings.ToLower(p.protocol), "https") {
		score += 2000
	}
	return score
}

func pickService(f *model.ScanFinding) *svcPick {
	if f.Port <= 0 {
		return nil
	}
	svc, _ := dataStr(f.Data, "service")
	ver, _ := dataStr(f.Data, "version")
	proto := strings.TrimSpace(f.Protocol)
	if proto == "" {
		proto = svc
	}
	return &svcPick{
		port:     f.Port,
		protocol: proto,
		service:  svc,
		version:  ver,
		conf:     f.Confidence,
	}
}
