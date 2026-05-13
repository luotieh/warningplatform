package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/model"

	"golang.org/x/net/html"
	"gorm.io/gorm"
)

// ══ 结果处理 ══

func (s *serviceMonitor) FetchTaskMeta(_ context.Context, url string) (string, string, error) {
	title := fetchPageTitle(url)
	return title, url, nil
}

func fetchPageTitle(targetURL string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return ""
	}
	return extractTitle(doc)
}

func extractTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" {
		if n.FirstChild != nil {
			return strings.TrimSpace(n.FirstChild.Data)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := extractTitle(c); t != "" {
			return t
		}
	}
	return ""
}

// HandleAgentResult 处理 Agent 上报的检测结果（HTTP API 入口）
func (s *serviceMonitor) HandleAgentResult(ctx context.Context, ar *model.MonitorAgentResult) {
	session := s.session()
	if session == nil {
		slog.Error("[AgentAPI] DB session error")
		return
	}

	startedAt := parseTime(ar.StartedAt)
	finishedAt := parseTime(ar.FinishedAt)

	exec := model.MonitorExecution{}
	if err := session.Where("id = ?", ar.ExecutionID).First(&exec).Error; err != nil {
		slog.Error("[AgentAPI] execution not found", "eid", ar.ExecutionID)
		return
	}

	if exec.Status == "success" || exec.Status == "failed" {
		canOverride := exec.Status == "failed" && exec.ReapedAt != nil && ar.Status == "success"
		if !canOverride {
			slog.Debug("[AgentAPI] execution already terminal", "eid", ar.ExecutionID, "status", exec.Status)
			return
		}
	}

	txErr := session.Transaction(func(tx *gorm.DB) error {
		exec.AgentID = ar.AgentID
		exec.Status = ar.Status
		exec.Error = ar.Error
		exec.StartedAt = startedAt
		exec.FinishedAt = finishedAt
		exec.ResultJSON = ar.Result
		exec.ReapedAt = nil

		if ar.Status == "failed" {
			return tx.Save(&exec).Error
		}

		saveFn := s.buildResultSaver(tx)
		saveFn(&exec, ar)

		if exec.HasIssue {
			exec.Disposition = model.MonitorDispositionPending
		} else {
			exec.Disposition = model.MonitorDispositionValid
		}

		return tx.Save(&exec).Error
	})

	if txErr != nil {
		slog.Error("[AgentAPI] save result failed", "error", txErr, "eid", ar.ExecutionID)
	} else {
		slog.Info("[AgentAPI] result processed", "eid", ar.ExecutionID, "dim", ar.Dimension, "status", ar.Status)
	}
}

func (s *serviceMonitor) buildResultSaver(tx *gorm.DB) func(*model.MonitorExecution, *model.MonitorAgentResult) {
	nats := s.nats
	return func(exec *model.MonitorExecution, ar *model.MonitorAgentResult) {
		switch ar.Dimension {
		case "sensitive_word":
			var r model.MonitorSensitiveWordResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if nats != nil {
					_ = nats.saveSensitiveWordResult(tx, ar.ExecutionID, ar.TaskID, &r)
				}
			}
		case "sensitive_file":
			var r model.MonitorSensitiveFileResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if nats != nil {
					_ = nats.saveSensitiveFileResult(tx, ar.ExecutionID, ar.TaskID, &r)
				}
			}
		case "tamper":
			var tr model.MonitorTamperResult
			if err := json.Unmarshal([]byte(ar.Result), &tr); err != nil {
				exec.HasIssue = jsonBool(ar.Result, "tampered")
			} else {
				exec.HasIssue = tr.Tampered
				if tr.BaselineUpdate != nil && nats != nil {
					_ = nats.saveBaselineFromResult(tx, ar.ExecutionID, ar.URL, ar.AgentID, tr.BaselineUpdate)
				}
			}
		case "blacklink":
			exec.HasIssue = jsonBool(ar.Result, "has_black")
		case "availability":
			exec.HasIssue = !jsonBool(ar.Result, "available")
		case "domain_hijack":
			exec.HasIssue = jsonBool(ar.Result, "hijacked")
		}
	}
}
