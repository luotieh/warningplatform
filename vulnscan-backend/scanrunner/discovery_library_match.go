package scanrunner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

// DiscoveryCandidateDedupKey 同一探测任务内按主机地址去重（不含端口）。
func DiscoveryCandidateDedupKey(address string) string {
	return discoveryCandidateHostKey(address)
}

// DiscoveryCanonicalHost 规范化候选地址（IPv4 标准形式，域名小写）。
func DiscoveryCanonicalHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return strings.ToLower(raw)
}

// DedupeDiscoveryCandidateRows 列表层按地址去重（保留先出现的记录）。
func DedupeDiscoveryCandidateRows(items []model.AssetDiscoveryCandidate, total int) ([]model.AssetDiscoveryCandidate, int) {
	if len(items) == 0 {
		return items, total
	}
	seen := map[string]struct{}{}
	out := make([]model.AssetDiscoveryCandidate, 0, len(items))
	for i := range items {
		key := DiscoveryCandidateDedupKey(items[i].Address)
		if key == "" {
			out = append(out, items[i])
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, items[i])
	}
	if total > len(out) {
		total = len(out)
	}
	return out, total
}

func discoveryCandidateHostKey(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(h)
	}
	if idx := strings.Index(raw, "/"); idx > 0 {
		raw = raw[:idx]
	}
	return raw
}

func discoveryAssetLedgerHostKey(a *model.Asset) string {
	if a == nil {
		return ""
	}
	if ip := strings.TrimSpace(a.IPv4); ip != "" {
		return strings.ToLower(ip)
	}
	return discoveryCandidateHostKey(a.Address)
}

// ApplyLibraryMatchToDiscoveryCandidates 对照资产台账标记「已在库」候选，无需再走下发核验/入库。
func ApplyLibraryMatchToDiscoveryCandidates(db *gorm.DB, items []model.AssetDiscoveryCandidate) {
	if db == nil || len(items) == 0 {
		return
	}
	hostSet := map[string]struct{}{}
	for i := range items {
		if h := discoveryCandidateHostKey(items[i].Address); h != "" {
			hostSet[h] = struct{}{}
		}
	}
	if len(hostSet) == 0 {
		return
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}

	var assets []model.Asset
	if err := db.Model(&model.Asset{}).
		Select("id", "name", "address", "ipv4", "port", "organize_id").
		Where("status = ?", 1).
		Where("ipv4 IN ? OR address IN ?", hosts, hosts).
		Find(&assets).Error; err != nil {
		return
	}
	if len(assets) < len(hosts) {
		var extra []model.Asset
		likeTx := db.Model(&model.Asset{}).
			Select("id", "name", "address", "ipv4", "port", "organize_id").
			Where("status = ?", 1)
		for i, h := range hosts {
			if i == 0 {
				likeTx = likeTx.Where("address LIKE ?", h+":%")
			} else {
				likeTx = likeTx.Or("address LIKE ?", h+":%")
			}
		}
		if err := likeTx.Find(&extra).Error; err == nil {
			seen := make(map[string]struct{}, len(assets))
			for i := range assets {
				seen[assets[i].ID] = struct{}{}
			}
			for i := range extra {
				if _, ok := seen[extra[i].ID]; !ok {
					assets = append(assets, extra[i])
					seen[extra[i].ID] = struct{}{}
				}
			}
		}
	}
	if len(assets) == 0 {
		return
	}

	byHost := map[string]*model.Asset{}
	byHostPort := map[string]*model.Asset{}
	for i := range assets {
		a := &assets[i]
		host := discoveryAssetLedgerHostKey(a)
		if host == "" {
			continue
		}
		if _, ok := byHost[host]; !ok {
			byHost[host] = a
		}
		if a.Port > 0 {
			key := fmt.Sprintf("%s|%d", host, a.Port)
			if _, ok := byHostPort[key]; !ok {
				byHostPort[key] = a
			}
		}
	}

	orgIDs := map[string]struct{}{}
	for i := range items {
		host := discoveryCandidateHostKey(items[i].Address)
		if host == "" {
			continue
		}
		var matched *model.Asset
		if items[i].Port > 0 {
			matched = byHostPort[fmt.Sprintf("%s|%d", host, items[i].Port)]
		}
		if matched == nil {
			matched = byHost[host]
		}
		if matched == nil {
			continue
		}
		items[i].InAssetLibrary = true
		items[i].ExistingAssetID = matched.ID
		items[i].ExistingOrganizeID = matched.OrganizeID
		items[i].ImportedID = matched.ID
		if matched.OrganizeID != "" {
			orgIDs[matched.OrganizeID] = struct{}{}
		}
		switch items[i].Status {
		case model.AssetDiscoveryCandidatePending, "":
			items[i].Status = model.AssetDiscoveryCandidateInLibrary
		}
	}

	if len(orgIDs) == 0 {
		return
	}
	ids := make([]string, 0, len(orgIDs))
	for id := range orgIDs {
		ids = append(ids, id)
	}
	var orgs []model.Organize
	if err := db.Where("id IN ?", ids).Find(&orgs).Error; err != nil {
		return
	}
	nameByID := make(map[string]string, len(orgs))
	for _, o := range orgs {
		nameByID[o.ID] = o.Name
	}
	for i := range items {
		if !items[i].InAssetLibrary {
			continue
		}
		if n, ok := nameByID[items[i].ExistingOrganizeID]; ok {
			items[i].ExistingOrganizeName = n
		}
	}
}

// PersistDiscoveryLibraryMatches 将列表中已识别为台账已有的候选写回数据库。
func PersistDiscoveryLibraryMatches(db *gorm.DB, items []model.AssetDiscoveryCandidate) {
	if db == nil {
		return
	}
	now := time.Now()
	for i := range items {
		if items[i].ID == "" || items[i].Status != model.AssetDiscoveryCandidateInLibrary {
			continue
		}
		_ = db.Model(&model.AssetDiscoveryCandidate{}).
			Where("id = ? AND status = ?", items[i].ID, model.AssetDiscoveryCandidatePending).
			Updates(map[string]interface{}{
				"status":            model.AssetDiscoveryCandidateInLibrary,
				"imported_asset_id": items[i].ImportedID,
				"updated_at":        now,
			}).Error
	}
}
