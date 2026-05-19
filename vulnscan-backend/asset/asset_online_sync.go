package asset

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"
	"vulnscan-backend/monitoragent"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	assetOnlineSyncMaxAssets     = 100
	assetOnlineSyncConcurrency   = 32
	assetOnlineSyncPerAssetTime  = 6 * time.Second
	assetOnlineSyncTCPTimeout    = 3 * time.Second
	assetOnlineSyncOverallBudget = 45 * time.Second
	assetOnlineProbeCooldown     = 5 * time.Minute
)

type assetOnlineSyncResult struct {
	Checked          int `json:"checked"`
	Online           int `json:"online"`
	Offline          int `json:"offline"`
	Skipped          int `json:"skipped"`
	SkippedRecent    int `json:"skipped_recent"`
	SkippedNotOnline int `json:"skipped_not_online"`
	DurationMS       int `json:"duration_ms"`
}

type assetOnlineProbe struct {
	assetID string
	mode    string // http | tcp
	target  string
}

type syncOnlineStatusReq struct {
	AssetIDs []string `json:"asset_ids"`
}

// SyncOnlineStatus 轻量可用性探测（HEAD/短超时），批量刷新 reachable；不改动 is_online，不创建监测任务。
func (h *EnrichHandler) SyncOnlineStatus(c *gin.Context) {
	listQuery, ok := web.BindQuery[assetContract.AssetQuery](c)
	if !ok {
		return
	}
	var body syncOnlineStatusReq
	if c.Request.ContentLength > 0 {
		_ = c.ShouldBindJSON(&body)
	}

	scope := iamsdk.DataFilterScope(c, assetFieldMapping)
	sess := h.session()
	tx := buildAssetListQuery(sess, listQuery, scope).Where("is_online = ?", true)

	var requestedIDs []string
	if len(body.AssetIDs) > 0 {
		for _, id := range body.AssetIDs {
			id = strings.TrimSpace(id)
			if id != "" {
				requestedIDs = append(requestedIDs, id)
			}
		}
		if len(requestedIDs) > assetOnlineSyncMaxAssets {
			requestedIDs = requestedIDs[:assetOnlineSyncMaxAssets]
		}
		tx = tx.Where("id IN ?", requestedIDs)
	} else {
		tx = tx.Order("updated_at DESC").Limit(assetOnlineSyncMaxAssets)
	}

	var assets []model.Asset
	if err := tx.Find(&assets).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	result := assetOnlineSyncResult{}
	if len(requestedIDs) > 0 {
		var notOnline int64
		_ = buildAssetListQuery(sess, listQuery, scope).
			Where("id IN ? AND is_online = ?", requestedIDs, false).
			Count(&notOnline).Error
		result.SkippedNotOnline = int(notOnline)
	}

	toProbe, skippedRecent := filterAssetsForProbeCooldown(assets)
	result.SkippedRecent = skippedRecent

	taskByAsset := loadMonitorPathTasksByAssetID(sess, toProbe)
	ctx, cancel := context.WithTimeout(c.Request.Context(), assetOnlineSyncOverallBudget)
	defer cancel()

	start := time.Now()
	probeResult := runAssetOnlineSync(ctx, sess, toProbe, taskByAsset)
	result.Checked = probeResult.Checked
	result.Online = probeResult.Online
	result.Offline = probeResult.Offline
	result.Skipped += probeResult.Skipped
	result.DurationMS = int(time.Since(start).Milliseconds())

	web.OK(c).Data(result).Send()
}

func loadMonitorPathTasksByAssetID(sess *gorm.DB, assets []model.Asset) map[string]*model.MonitorPathTask {
	out := map[string]*model.MonitorPathTask{}
	if sess == nil || len(assets) == 0 {
		return out
	}
	ids := make([]string, 0, len(assets))
	for _, a := range assets {
		if a.ID != "" {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	var tasks []model.MonitorPathTask
	_ = sess.Where("asset_id IN ? AND enabled = ?", ids, true).Find(&tasks).Error
	for i := range tasks {
		t := tasks[i]
		if t.AssetID == "" {
			continue
		}
		if cur, ok := out[t.AssetID]; !ok || preferMonitorPathTask(&t, cur) {
			copy := t
			out[t.AssetID] = &copy
		}
	}
	return out
}

func preferMonitorPathTask(candidate, current *model.MonitorPathTask) bool {
	if current == nil {
		return true
	}
	if monitorAvailabilityEnabled(candidate) && !monitorAvailabilityEnabled(current) {
		return true
	}
	return false
}

func filterAssetsForProbeCooldown(assets []model.Asset) ([]model.Asset, int) {
	cutoff := time.Now().Add(-assetOnlineProbeCooldown)
	out := make([]model.Asset, 0, len(assets))
	skipped := 0
	for _, asset := range assets {
		if asset.ReachableCheckedAt != nil && asset.ReachableCheckedAt.After(cutoff) {
			skipped++
			continue
		}
		out = append(out, asset)
	}
	return out, skipped
}

func monitorAvailabilityEnabled(task *model.MonitorPathTask) bool {
	if task == nil {
		return false
	}
	cfg := task.GetDimensionConfig("availability")
	if cfg == nil {
		return true
	}
	if v, ok := cfg["enabled"].(bool); ok {
		return v
	}
	return true
}

func runAssetOnlineSync(ctx context.Context, sess *gorm.DB, assets []model.Asset, taskByAsset map[string]*model.MonitorPathTask) assetOnlineSyncResult {
	result := assetOnlineSyncResult{}
	if len(assets) == 0 {
		return result
	}

	type outcome struct {
		assetID string
		online  bool
		skipped bool
	}
	outCh := make(chan outcome, len(assets))
	sem := make(chan struct{}, assetOnlineSyncConcurrency)
	var wg sync.WaitGroup

	for _, asset := range assets {
		asset := asset
		probe, ok := buildAssetOnlineProbe(asset, taskByAsset[asset.ID])
		if !ok {
			result.Skipped++
			continue
		}
		result.Checked++
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probeCtx, cancel := context.WithTimeout(ctx, assetOnlineSyncPerAssetTime)
			defer cancel()

			online := probeAssetOnline(probeCtx, probe)
			outCh <- outcome{assetID: asset.ID, online: online}
		}()
	}

	wg.Wait()
	close(outCh)

	updates := make(map[string]bool, result.Checked)
	for o := range outCh {
		if o.skipped {
			continue
		}
		updates[o.assetID] = o.online
		if o.online {
			result.Online++
		} else {
			result.Offline++
		}
	}
	persistAssetReachableFlags(sess, updates)
	return result
}

func buildAssetOnlineProbe(asset model.Asset, task *model.MonitorPathTask) (assetOnlineProbe, bool) {
	if task != nil && strings.TrimSpace(task.URLOverride) != "" && monitorAvailabilityEnabled(task) {
		if url := normalizeAssetProbeHTTPURL(task.URLOverride); url != "" {
			return assetOnlineProbe{assetID: asset.ID, mode: "http", target: url}, true
		}
	}

	if url := normalizeAssetProbeHTTPURL(firstNonEmpty(asset.URL, asset.Address)); url != "" {
		return assetOnlineProbe{assetID: asset.ID, mode: "http", target: url}, true
	}
	if asset.Domain != "" {
		host := asset.Domain
		if asset.Port > 0 {
			host = net.JoinHostPort(asset.Domain, strconv.Itoa(asset.Port))
		}
		if url := normalizeAssetProbeHTTPURL(host); url != "" {
			return assetOnlineProbe{assetID: asset.ID, mode: "http", target: url}, true
		}
	}
	if asset.IPv4 != "" {
		host := asset.IPv4
		port := asset.Port
		if port <= 0 {
			port = 80
		}
		host = net.JoinHostPort(host, strconv.Itoa(port))
		if strings.HasPrefix(asset.Address, "http://") || strings.HasPrefix(asset.Address, "https://") {
			if url := normalizeAssetProbeHTTPURL(asset.Address); url != "" {
				return assetOnlineProbe{assetID: asset.ID, mode: "http", target: url}, true
			}
		}
		return assetOnlineProbe{assetID: asset.ID, mode: "tcp", target: host}, true
	}
	return assetOnlineProbe{}, false
}

func normalizeAssetProbeHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.Contains(raw, "://") {
		return ""
	}
	return "http://" + raw
}

func probeAssetOnline(ctx context.Context, probe assetOnlineProbe) bool {
	switch probe.mode {
	case "http":
		return monitoragent.ProbeHTTPReachable(ctx, probe.target)
	case "tcp":
		return probeTCPReachable(ctx, probe.target)
	default:
		return false
	}
}

func probeTCPReachable(ctx context.Context, hostPort string) bool {
	d := net.Dialer{Timeout: assetOnlineSyncTCPTimeout}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func persistAssetReachableFlags(sess *gorm.DB, updates map[string]bool) {
	if sess == nil || len(updates) == 0 {
		return
	}
	now := time.Now()
	_ = sess.Transaction(func(tx *gorm.DB) error {
		for id, online := range updates {
			reachable := online
			if err := tx.Model(&model.Asset{}).Where("id = ?", id).Updates(map[string]any{
				"reachable":            reachable,
				"reachable_checked_at": now,
				"updated_at":           now,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
