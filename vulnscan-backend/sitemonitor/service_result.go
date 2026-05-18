package sitemonitor

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/model"

	"golang.org/x/net/html"
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

// HandleAgentResult 处理 Agent 上报的检测结果（HTTP API / NATS 入口）
func (s *serviceMonitor) HandleAgentResult(ctx context.Context, ar *model.MonitorAgentResult) {
	session := s.session()
	if session == nil {
		slog.Error("[AgentAPI] DB session error")
		return
	}
	if err := FinalizeMonitorResult(ctx, session, ar); err != nil {
		slog.Error("[AgentAPI] save result failed", "error", err, "eid", ar.ExecutionID)
		return
	}
	slog.Info("[AgentAPI] result processed", "eid", ar.ExecutionID, "dim", ar.Dimension, "status", ar.Status)
}
