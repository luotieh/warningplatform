package intel

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

func (h *Handler) ListIOC(c *gin.Context) {
	iocType := c.Query("type")
	severity := c.Query("severity")
	keyword := c.Query("q")

	var items []model.IOCIndicator
	tx := h.db.Model(&model.IOCIndicator{})

	if iocType != "" {
		tx = tx.Where("type = ?", iocType)
	}
	if severity != "" {
		tx = tx.Where("severity = ?", severity)
	}
	if keyword != "" {
		tx = tx.Where("value LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var count int64
	tx.Count(&count)
	tx.Order("created_at DESC").Limit(200).Find(&items)

	web.OK(c).List(count, items).Send()
}

func (h *Handler) CreateIOC(c *gin.Context) {
	req, ok := web.BindJSON[CreateIOCReq](c)
	if !ok {
		return
	}

	ioc := model.IOCIndicator{
		ID:          qulid.GenerateID(),
		Type:        req.Type,
		Value:       strings.TrimSpace(req.Value),
		ThreatType:  req.ThreatType,
		Severity:    req.Severity,
		Source:      req.Source,
		Description: req.Description,
		Tags:        model.StringArray(req.Tags),
		Enabled:     true,
	}

	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		if t, err := time.Parse("2006-01-02", *req.ExpiresAt); err == nil {
			ioc.ExpiresAt = &t
		}
	}

	if err := h.db.Create(&ioc).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(ioc).Send()
}

func (h *Handler) BatchImportIOC(c *gin.Context) {
	req, ok := web.BindJSON[BatchImportIOCReq](c)
	if !ok {
		return
	}
	if len(req.Items) == 0 {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var iocs []model.IOCIndicator
	for _, item := range req.Items {
		val := strings.TrimSpace(item.Value)
		if val == "" {
			continue
		}
		iocs = append(iocs, model.IOCIndicator{
			ID:          qulid.GenerateID(),
			Type:        item.Type,
			Value:       val,
			ThreatType:  item.ThreatType,
			Severity:    item.Severity,
			Source:      item.Source,
			Description: item.Description,
			Enabled:     true,
		})
	}

	if len(iocs) == 0 {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	if err := h.db.CreateInBatches(iocs, 100).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"imported": len(iocs)}).Send()
}

func (h *Handler) DeleteIOC(c *gin.Context) {
	id := c.Param("id")
	h.db.Where("id = ?", id).Delete(&model.IOCIndicator{})
	web.OK(c).Send()
}

func (h *Handler) ToggleIOC(c *gin.Context) {
	id := c.Param("id")
	var ioc model.IOCIndicator
	if err := h.db.Where("id = ?", id).First(&ioc).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	h.db.Model(&ioc).Update("enabled", !ioc.Enabled)
	web.OK(c).Send()
}

func (h *Handler) CheckIOC(c *gin.Context) {
	req, ok := web.BindJSON[CheckIOCReq](c)
	if !ok {
		return
	}
	if len(req.Values) == 0 {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var indicators []model.IOCIndicator
	h.db.Where("value IN ? AND enabled = ?", req.Values, true).Find(&indicators)

	now := time.Now()
	var hits []model.IOCIndicator
	for i := range indicators {
		ind := &indicators[i]
		if ind.ExpiresAt != nil && ind.ExpiresAt.Before(now) {
			continue
		}
		hits = append(hits, *ind)
		h.db.Model(ind).Updates(map[string]interface{}{
			"hit_count":   ind.HitCount + 1,
			"last_hit_at": &now,
		})
	}

	web.OK(c).Data(gin.H{
		"checked": len(req.Values),
		"hits":    len(hits),
		"matches": hits,
	}).Send()
}

func (h *Handler) ScanAssetsIOC(c *gin.Context) {
	var indicators []model.IOCIndicator
	now := time.Now()
	h.db.Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, now).Find(&indicators)
	if len(indicators) == 0 {
		web.OK(c).Data(gin.H{"message": "无有效IOC指标", "hits": 0}).Send()
		return
	}

	ipIOCs := make(map[string]*model.IOCIndicator)
	domainIOCs := make(map[string]*model.IOCIndicator)
	for i := range indicators {
		switch indicators[i].Type {
		case model.IOCTypeIP:
			ipIOCs[indicators[i].Value] = &indicators[i]
		case model.IOCTypeDomain:
			domainIOCs[strings.ToLower(indicators[i].Value)] = &indicators[i]
		}
	}

	var assets []model.Asset
	h.db.Select("id, name, ipv4, domain").Find(&assets)

	type hitResult struct {
		AssetID   string `json:"asset_id"`
		AssetName string `json:"asset_name"`
		IOCType   string `json:"ioc_type"`
		IOCValue  string `json:"ioc_value"`
		Severity  string `json:"severity"`
	}

	var hits []hitResult
	for _, asset := range assets {
		if ioc, ok := ipIOCs[asset.IPv4]; ok {
			hits = append(hits, hitResult{
				AssetID: asset.ID, AssetName: asset.Name,
				IOCType: "ip", IOCValue: ioc.Value, Severity: ioc.Severity,
			})
			h.db.Model(ioc).Updates(map[string]interface{}{"hit_count": ioc.HitCount + 1, "last_hit_at": &now})
		}
		if asset.Domain != "" {
			if ioc, ok := domainIOCs[strings.ToLower(asset.Domain)]; ok {
				hits = append(hits, hitResult{
					AssetID: asset.ID, AssetName: asset.Name,
					IOCType: "domain", IOCValue: ioc.Value, Severity: ioc.Severity,
				})
				h.db.Model(ioc).Updates(map[string]interface{}{"hit_count": ioc.HitCount + 1, "last_hit_at": &now})
			}
		}
	}

	if len(hits) > 0 {
		for _, hit := range hits {
			n := model.Notification{
				ID:       qulid.GenerateID(),
				Type:     model.NotifyTypeIOCHit,
				Title:    fmt.Sprintf("[IOC命中] %s (%s)", hit.IOCValue, hit.IOCType),
				Content:  fmt.Sprintf("资产「%s」(%s) 匹配到威胁指标 %s", hit.AssetName, hit.AssetID, hit.IOCValue),
				Link:     fmt.Sprintf("/asset/ledger?id=%s", hit.AssetID),
				Severity: hit.Severity,
			}
			h.db.Create(&n)
		}
		slog.Info("[+] IOC扫描发现命中", "hits", len(hits))
	}

	web.OK(c).Data(gin.H{
		"scanned_assets": len(assets),
		"ioc_count":      len(indicators),
		"hits":           len(hits),
		"results":        hits,
	}).Send()
}

func (h *Handler) GetIOCStats(c *gin.Context) {
	var total, enabled, expired int64
	h.db.Model(&model.IOCIndicator{}).Count(&total)
	h.db.Model(&model.IOCIndicator{}).Where("enabled = ?", true).Count(&enabled)
	h.db.Model(&model.IOCIndicator{}).Where("expires_at < ?", time.Now()).Count(&expired)

	typeStats := make(map[string]int64)
	var results []struct {
		Type  string
		Count int64
	}
	h.db.Model(&model.IOCIndicator{}).Select("type, count(*) as count").Group("type").Scan(&results)
	for _, r := range results {
		typeStats[r.Type] = r.Count
	}

	web.OK(c).Data(gin.H{
		"total":   total,
		"enabled": enabled,
		"expired": expired,
		"by_type": typeStats,
	}).Send()
}
