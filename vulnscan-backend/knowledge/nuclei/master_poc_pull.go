package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	fedSync "vulnscan-backend/federation/sync"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

const masterPocPullLimit = 500

// tryPullPocFromMaster 从主控 node-api 增量拉取 PoC 写入本地库（与联邦子控 apply 语义一致）。
// 需配置环境变量 VULNSCAN_MASTER_API_BASE（如 https://主控域名/api）、VULNSCAN_NODE_AGENT_TOKEN（节点 UUID，与 X-Agent-Token 一致），
// 若主控该节点已配置密钥哈希，还需 VULNSCAN_NODE_AGENT_SECRET（与 X-Agent-Secret 一致）。
// 任务 parameters 中可提供 poc_master_api_base、node_agent_token、node_agent_secret。
// 未配置或显式 poc_master_pull_disable=true 时返回 (0, nil)。
func tryPullPocFromMaster(ctx context.Context, db *gorm.DB, config map[string]interface{}) (int, error) {
	if db == nil {
		return 0, nil
	}
	if boolFromConfig(config, "poc_master_pull_disable") {
		return 0, nil
	}
	base := strings.TrimSpace(configString(config, "poc_master_api_base", ""))
	if base == "" {
		base = strings.TrimSpace(os.Getenv("VULNSCAN_MASTER_API_BASE"))
	}
	base = strings.TrimRight(base, "/")
	if base == "" {
		return 0, nil
	}
	token := strings.TrimSpace(configString(config, "node_agent_token", ""))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VULNSCAN_NODE_AGENT_TOKEN"))
	}
	if token == "" {
		return 0, nil
	}
	secret := strings.TrimSpace(configString(config, "node_agent_secret", ""))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("VULNSCAN_NODE_AGENT_SECRET"))
	}

	var localMax int64
	if err := db.Model(&model.PocTemplate{}).Select("COALESCE(MAX(sync_version),0)").Scan(&localMax).Error; err != nil {
		return 0, fmt.Errorf("read local poc sync_version: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Minute}
	since := localMax
	totalApplied := 0

	for {
		if err := ctx.Err(); err != nil {
			return totalApplied, err
		}
		url := fmt.Sprintf("%s/node-api/knowledge/sync/poc?since_version=%d&limit=%d", base, since, masterPocPullLimit)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return totalApplied, err
		}
		req.Header.Set("X-Agent-Token", token)
		if secret != "" {
			req.Header.Set("X-Agent-Secret", secret)
		}

		resp, err := client.Do(req)
		if err != nil {
			return totalApplied, fmt.Errorf("master poc sync request: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return totalApplied, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return totalApplied, fmt.Errorf("master poc sync http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var syncResp fedSync.SyncResponse
		if err := json.Unmarshal(body, &syncResp); err != nil {
			return totalApplied, fmt.Errorf("decode sync response: %w", err)
		}
		if len(syncResp.Items) == 0 {
			break
		}
		n := applyPocSyncItems(db, syncResp.Items)
		totalApplied += n
		since = syncResp.Items[len(syncResp.Items)-1].SyncVersion
		if !syncResp.HasMore {
			break
		}
	}

	if totalApplied > 0 {
		slog.Info("[NucleiModule] 主控 PoC 同步完成", "applied", totalApplied, "since_was", localMax)
	}
	return totalApplied, nil
}

func applyPocSyncItems(db *gorm.DB, items []fedSync.SyncItem) int {
	n := 0
	for _, item := range items {
		if item.Action == "delete" {
			db.Where("poc_id = ? AND source_type = ?", item.DataID, "central").Delete(&model.PocTemplate{})
			n++
			continue
		}
		var rec model.PocTemplate
		if err := json.Unmarshal(item.Content, &rec); err != nil {
			slog.Debug("[NucleiModule] 跳过无法解析的 PoC 同步项", "data_id", item.DataID, "error", err)
			continue
		}
		rec.SourceType = "central"
		rec.SyncVersion = item.SyncVersion
		if err := db.Where("poc_id = ?", rec.PocID).Assign(rec).FirstOrCreate(&rec).Error; err != nil {
			slog.Warn("[NucleiModule] 写入同步 PoC 失败", "poc_id", rec.PocID, "error", err)
			continue
		}
		n++
	}
	return n
}
