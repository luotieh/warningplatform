package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/boot"
	fedSync "vulnscan-backend/federation/sync"
	"vulnscan-backend/model"
)

// Client is the federation client running on Sub-Master nodes.
type Client struct {
	config     boot.FederationUpstreamConfig
	db         *gorm.DB
	httpClient *http.Client

	subMasterCode string
	apiToken      string
	mu            sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

func New(cfg boot.FederationUpstreamConfig, db *gorm.DB) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	hostname, _ := os.Hostname()
	code := fmt.Sprintf("sm-%s-%d", hostname, os.Getpid())
	if env := os.Getenv("SUB_MASTER_CODE"); env != "" {
		code = env
	}

	return &Client{
		config:        cfg,
		db:            db,
		subMasterCode: code,
		ctx:           ctx,
		cancel:        cancel,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
}

// Start registers with central, then begins sync and heartbeat loops.
func (c *Client) Start() error {
	if c.config.CentralURL == "" {
		slog.Info("[FedClient] 无中心主控URL，跳过联邦同步")
		return nil
	}

	if err := c.register(); err != nil {
		slog.Error("[FedClient] 注册到中心主控失败", "error", err)
		return err
	}

	syncInterval, _ := time.ParseDuration(c.config.SyncInterval)
	if syncInterval < time.Minute {
		syncInterval = 10 * time.Minute
	}

	reportInterval, _ := time.ParseDuration(c.config.ReportInterval)
	if reportInterval < time.Minute {
		reportInterval = 5 * time.Minute
	}

	go c.syncLoop(syncInterval)
	go c.heartbeatLoop(30 * time.Second)
	go c.reportLoop(reportInterval)

	slog.Info("[FedClient] 联邦客户端已启动",
		"central", c.config.CentralURL,
		"sync_interval", syncInterval,
		"report_interval", reportInterval,
	)

	return nil
}

func (c *Client) Stop() {
	c.cancel()
}

func (c *Client) register() error {
	req := fedSync.RegisterRequest{
		SubMasterCode: c.subMasterCode,
		Hostname:      getHostname(),
		IPAddress:     "",
		Version:       "1.0.0",
		LicenseKey:    c.config.APIToken,
		Capabilities:  []string{"scan", "report"},
	}

	body, _ := json.Marshal(req)
	resp, err := c.doPost("/federation/v1/register", body, false)
	if err != nil {
		return fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register failed: %s %s", resp.Status, string(respBody))
	}

	var regResp fedSync.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}

	c.mu.Lock()
	c.apiToken = regResp.APIToken
	c.mu.Unlock()

	slog.Info("[FedClient] 注册成功",
		"quota_workers", regResp.Quota.MaxWorkers,
		"quota_targets", regResp.Quota.MaxTargets,
	)

	return nil
}

func (c *Client) heartbeatLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.sendHeartbeat()
		}
	}
}

func (c *Client) sendHeartbeat() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	req := fedSync.HeartbeatRequest{
		SubMasterCode: c.subMasterCode,
		MemPercent:    float64(m.Alloc) / float64(m.Sys) * 100,
	}

	states := c.getSyncStates()
	for _, s := range states {
		switch s.DataType {
		case model.SyncDataTypePoc:
			req.PocVersion = s.LocalVersion
		case model.SyncDataTypeFingerprint:
			req.FPVersion = s.LocalVersion
		case model.SyncDataTypeRule:
			req.RuleVersion = s.LocalVersion
		}
	}

	body, _ := json.Marshal(req)
	resp, err := c.doPost("/federation/v1/heartbeat", body, true)
	if err != nil {
		slog.Debug("[FedClient] 心跳发送失败", "error", err)
		return
	}
	defer resp.Body.Close()

	var hbResp fedSync.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hbResp); err == nil {
		for _, cmd := range hbResp.Commands {
			c.handleCommand(cmd)
		}

		if len(hbResp.CurrentVersions) > 0 {
			c.checkVersionDrift(hbResp.CurrentVersions)
		}
	}
}

// checkVersionDrift compares central versions with local state;
// triggers immediate sync for any data type that has fallen behind.
func (c *Client) checkVersionDrift(centralVersions map[string]int64) {
	states := c.getSyncStates()
	localMap := make(map[string]int64, len(states))
	for _, s := range states {
		localMap[s.DataType] = s.LocalVersion
	}

	for dt, centralVer := range centralVersions {
		localVer := localMap[dt]
		if centralVer > localVer {
			slog.Info("[FedClient] 检测到版本差异，触发即时同步",
				"type", dt,
				"local", localVer,
				"central", centralVer,
			)
			go c.syncDataType(dt)
		}
	}
}

func (c *Client) handleCommand(cmd fedSync.Command) {
	slog.Info("[FedClient] 收到中心命令", "type", cmd.Type)
	switch cmd.Type {
	case "force_sync":
		go c.syncAll()
	}
}

func (c *Client) syncLoop(interval time.Duration) {
	c.syncAll()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.syncAll()
		}
	}
}

func (c *Client) syncAll() {
	c.syncDataType(model.SyncDataTypePoc)
	c.syncDataType(model.SyncDataTypeFingerprint)
	c.syncDataType(model.SyncDataTypeRule)
}

func (c *Client) syncDataType(dataType string) {
	state := c.getOrCreateSyncState(dataType)

	for {
		url := fmt.Sprintf("/federation/v1/sync/%s?since_version=%d&limit=500", dataType, state.LocalVersion)

		resp, err := c.doGet(url)
		if err != nil {
			c.updateSyncError(dataType, err.Error())
			slog.Warn("[FedClient] 同步请求失败", "type", dataType, "error", err)
			return
		}

		var syncResp fedSync.SyncResponse
		if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
			resp.Body.Close()
			c.updateSyncError(dataType, err.Error())
			return
		}
		resp.Body.Close()

		if len(syncResp.Items) == 0 {
			break
		}

		if err := c.applyItems(dataType, syncResp.Items); err != nil {
			c.updateSyncError(dataType, err.Error())
			return
		}

		maxVer := syncResp.Items[len(syncResp.Items)-1].SyncVersion
		c.updateSyncState(dataType, maxVer)
		state.LocalVersion = maxVer

		slog.Info("[FedClient] 同步完成",
			"type", dataType,
			"records", len(syncResp.Items),
			"version", maxVer,
		)

		if !syncResp.HasMore {
			break
		}
	}
}

func (c *Client) applyItems(dataType string, items []fedSync.SyncItem) error {
	for _, item := range items {
		if item.Action == "delete" {
			c.deleteLocal(dataType, item.DataID)
			continue
		}

		switch dataType {
		case model.SyncDataTypePoc:
			var rec model.PocTemplate
			if err := json.Unmarshal(item.Content, &rec); err != nil {
				continue
			}
			rec.SourceType = "central"
			rec.SyncVersion = item.SyncVersion
			c.db.Where("poc_id = ?", rec.PocID).Assign(rec).FirstOrCreate(&rec)

		case model.SyncDataTypeFingerprint:
			var rec model.ServiceFingerprint
			if err := json.Unmarshal(item.Content, &rec); err != nil {
				continue
			}
			rec.SourceType = "central"
			rec.SyncVersion = item.SyncVersion
			c.db.Where("id = ?", rec.ID).Assign(rec).FirstOrCreate(&rec)

		case model.SyncDataTypeRule:
			var rec model.ScanRule
			if err := json.Unmarshal(item.Content, &rec); err != nil {
				continue
			}
			rec.SourceType = "central"
			rec.SyncVersion = item.SyncVersion
			c.db.Where("id = ?", rec.ID).Assign(rec).FirstOrCreate(&rec)
		}
	}
	return nil
}

func (c *Client) deleteLocal(dataType, dataID string) {
	switch dataType {
	case model.SyncDataTypePoc:
		c.db.Where("poc_id = ? AND source_type = ?", dataID, "central").Delete(&model.PocTemplate{})
	case model.SyncDataTypeFingerprint:
		c.db.Where("id = ? AND source_type = ?", dataID, "central").Delete(&model.ServiceFingerprint{})
	case model.SyncDataTypeRule:
		c.db.Where("id = ? AND source_type = ?", dataID, "central").Delete(&model.ScanRule{})
	}
}

func (c *Client) reportLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.flushReportBuffer()
		}
	}
}

func (c *Client) flushReportBuffer() {
	var buffers []model.FederationReportBuffer
	c.db.Where("status = ?", "pending").Order("created_at ASC").Limit(100).Find(&buffers)

	for _, buf := range buffers {
		var url string
		switch buf.ReportType {
		case "vuln_summary":
			url = "/federation/v1/report/vuln"
		case "scan_stats":
			url = "/federation/v1/report/scan"
		default:
			continue
		}

		body, _ := json.Marshal(buf.Payload)
		resp, err := c.doPost(url, body, true)
		if err != nil {
			c.db.Model(&buf).Updates(map[string]interface{}{
				"retry_count": gorm.Expr("retry_count + 1"),
				"status":      "failed",
			})
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			c.db.Model(&buf).Update("status", "sent")
		} else {
			c.db.Model(&buf).Updates(map[string]interface{}{
				"retry_count": gorm.Expr("retry_count + 1"),
			})
		}
	}
}

// --- helpers ---

func (c *Client) doGet(path string) (*http.Response, error) {
	c.mu.RLock()
	token := c.apiToken
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.config.CentralURL+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.httpClient.Do(req)
}

func (c *Client) doPost(path string, body []byte, auth bool) (*http.Response, error) {
	c.mu.RLock()
	token := c.apiToken
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.config.CentralURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.httpClient.Do(req)
}

func (c *Client) getOrCreateSyncState(dataType string) model.FederationSyncState {
	var state model.FederationSyncState
	c.db.Where("data_type = ?", dataType).FirstOrCreate(&state, model.FederationSyncState{
		DataType: dataType,
	})
	return state
}

func (c *Client) getSyncStates() []model.FederationSyncState {
	var states []model.FederationSyncState
	c.db.Find(&states)
	return states
}

func (c *Client) updateSyncState(dataType string, version int64) {
	now := time.Now()
	c.db.Model(&model.FederationSyncState{}).Where("data_type = ?", dataType).Updates(map[string]interface{}{
		"local_version": version,
		"last_sync_at":  now,
		"last_error":    "",
		"retry_count":   0,
	})
}

func (c *Client) updateSyncError(dataType, errMsg string) {
	c.db.Model(&model.FederationSyncState{}).Where("data_type = ?", dataType).Updates(map[string]interface{}{
		"last_error":  errMsg,
		"retry_count": gorm.Expr("retry_count + 1"),
	})
}

func getHostname() string {
	h, _ := os.Hostname()
	return h
}
