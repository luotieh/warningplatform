package scanrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// AlerterConfig configures the alerting system.
type AlerterConfig struct {
	WebhookURL        string
	Enabled           bool
	AlertOnTaskFail   bool
	AlertOnWorkerDown bool
	AlertOnHighVuln   bool
	CooldownMinutes   int
}

// Alerter sends notifications on critical events (worker down, task failed, high/critical vulns).
type Alerter struct {
	db     *gorm.DB
	config AlerterConfig

	mu       sync.Mutex
	cooldown map[string]time.Time
}

func NewAlerter(db *gorm.DB, config AlerterConfig) *Alerter {
	if config.CooldownMinutes <= 0 {
		config.CooldownMinutes = 10
	}
	return &Alerter{
		db:       db,
		config:   config,
		cooldown: make(map[string]time.Time),
	}
}

type AlertPayload struct {
	Level     string                 `json:"level"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (a *Alerter) AlertWorkerDown(worker model.WorkerNode) {
	if !a.config.Enabled || !a.config.AlertOnWorkerDown {
		return
	}

	key := "worker_down:" + worker.ID
	if a.isInCooldown(key) {
		return
	}

	payload := AlertPayload{
		Level:     "warning",
		Title:     "扫描节点失联",
		Message:   fmt.Sprintf("Worker %s (%s / %s) 已失联", worker.ID, worker.Hostname, worker.IP),
		Source:    "vulnscan-scheduler",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"worker_id":      worker.ID,
			"hostname":       worker.Hostname,
			"ip":             worker.IP,
			"last_heartbeat": worker.LastHeartbeat,
		},
	}

	a.send(payload)
	a.setCooldown(key)
}

func (a *Alerter) AlertTaskFailed(task model.ScanTask) {
	if !a.config.Enabled || !a.config.AlertOnTaskFail {
		return
	}

	key := "task_fail:" + task.ID
	if a.isInCooldown(key) {
		return
	}

	payload := AlertPayload{
		Level:     "error",
		Title:     "扫描任务失败",
		Message:   fmt.Sprintf("任务 %s (%s) 执行失败: %s", task.ID, task.Name, task.ErrorMsg),
		Source:    "vulnscan-scheduler",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"task_id":   task.ID,
			"name":      task.Name,
			"targets":   len(task.Targets),
			"error_msg": task.ErrorMsg,
			"worker_id": task.WorkerID,
		},
	}

	a.send(payload)
	a.setCooldown(key)
}

func (a *Alerter) AlertHighVulnerability(taskID string, vulnCount int, severity string) {
	if !a.config.Enabled || !a.config.AlertOnHighVuln {
		return
	}

	key := fmt.Sprintf("high_vuln:%s:%s", taskID, severity)
	if a.isInCooldown(key) {
		return
	}

	payload := AlertPayload{
		Level:     "critical",
		Title:     "发现高危漏洞",
		Message:   fmt.Sprintf("任务 %s 发现 %d 个 %s 级别漏洞", taskID, vulnCount, severity),
		Source:    "vulnscan-scheduler",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"task_id":    taskID,
			"severity":   severity,
			"vuln_count": vulnCount,
		},
	}

	a.send(payload)
	a.setCooldown(key)
}

func (a *Alerter) send(payload AlertPayload) {
	if a.config.WebhookURL == "" {
		slog.Info("[Alerter] 告警(无Webhook)",
			"level", payload.Level, "title", payload.Title, "message", payload.Message)
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("[Alerter] 发送告警 panic", "panic", r)
			}
		}()

		body, err := json.Marshal(payload)
		if err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			slog.Warn("[Alerter] 告警发送失败", "error", err, "url", a.config.WebhookURL)
			return
		}
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			slog.Warn("[Alerter] 告警接收方返回错误", "status", resp.StatusCode)
		}
	}()
}

func (a *Alerter) isInCooldown(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if until, ok := a.cooldown[key]; ok {
		if time.Now().Before(until) {
			return true
		}
	}
	return false
}

func (a *Alerter) setCooldown(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cooldown[key] = time.Now().Add(time.Duration(a.config.CooldownMinutes) * time.Minute)
}
