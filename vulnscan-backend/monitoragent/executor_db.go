package monitoragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/sitemonitor/analyzer"

	"gorm.io/gorm"
)

type DBExecutor struct {
	db          *gorm.DB
	pageService *PageService
	analysis    *AnalysisEngine
}

func NewDBExecutor(db *gorm.DB) *DBExecutor {
	return &DBExecutor{db: db}
}

func (e *DBExecutor) Type() string { return "monitor" }

func (e *DBExecutor) Init(ctx context.Context) error {
	e.pageService = NewPageService()
	e.loadScreenshotConfig()
	e.analysis = NewAnalysisEngineFromDB(e.db)
	e.analysis.RefreshRules(ctx)
	return nil
}

func (e *DBExecutor) loadScreenshotConfig() {
	if e.db == nil || e.pageService == nil {
		return
	}
	type cfgRow struct {
		ConfigJSON string `gorm:"column:config_json"`
	}
	var row cfgRow
	if err := e.db.Table("monitor_default_configs").Where("dimension = ?", "screenshot").Select("config_json").First(&row).Error; err != nil {
		return
	}
	var cfg ScreenshotConfig
	if json.Unmarshal([]byte(row.ConfigJSON), &cfg) == nil {
		if cfg.Width > 0 {
			e.pageService.ScreenCfg.Width = cfg.Width
		}
		if cfg.Height > 0 {
			e.pageService.ScreenCfg.Height = cfg.Height
		}
		if cfg.Quality > 0 && cfg.Quality <= 100 {
			e.pageService.ScreenCfg.Quality = cfg.Quality
		}
		slog.Info("[Monitor] 截图配置已加载", "width", e.pageService.ScreenCfg.Width, "height", e.pageService.ScreenCfg.Height, "quality", e.pageService.ScreenCfg.Quality)
	}
}

func (e *DBExecutor) Execute(ctx context.Context, payload json.RawMessage) *agent.TaskResult {
	var msg TaskMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return &agent.TaskResult{
			Status:     "failed",
			Error:      "invalid monitor payload: " + err.Error(),
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	result := &agent.TaskResult{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}

	slog.Info("embedded monitor exec", "execution_id", msg.ExecutionID, "dimension", msg.Dimension, "url", msg.URL)

	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if msg.Dimension == "sensitive_file" {
		result.Status = "success"
		analyzed, aErr := e.analysis.Analyze(ctx, msg.Dimension, "", msg.URL, &msg)
		if aErr != nil {
			result.Status = "failed"
			result.Error = aErr.Error()
		} else {
			result.Result = analyzed
		}
		return result
	}

	snap, err := e.pageService.FetchPage(ctx, msg.URL, msg.RequestHost)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	result.Status = "success"
	if snap != nil {
		if len(snap.Screenshot) > 0 {
			result.ScreenshotData = snap.Screenshot
		}

		if (msg.Dimension == "blacklink" || msg.Dimension == "tamper") && e.pageService.HasBrowser() {
			finalURL, redirected := e.pageService.DetectBrowserRedirect(ctx, msg.URL, 5*time.Second)
			if redirected {
				snap.JSRedirects = append(snap.JSRedirects, JSRedirect{
					Type:   "browser_detected",
					Target: finalURL,
				})
				slog.Info("[Monitor] 浏览器检测到跳转", "dimension", msg.Dimension, "url", msg.URL, "final", finalURL)
			}
		}

		if msg.Dimension == "blacklink" {
			cloaking := e.pageService.DetectCloaking(ctx, msg.URL, snap.ContentHash, snap.Title, snap.VisibleText)
			if cloaking != nil && cloaking.Detected {
				slog.Info("[Monitor] 检测到SEO Cloaking", "url", msg.URL, "similarity", cloaking.Similarity)
			}
			if cloaking != nil {
				snap.CloakingResult = cloaking
			}
		}

		raw, _ := json.Marshal(snap)
		snapshotJSON := string(raw)

		analyzed, output, aErr := e.analysis.AnalyzeWithOutput(ctx, msg.Dimension, snapshotJSON, msg.URL, &msg)
		if aErr != nil {
			slog.Warn("analysis failed, using raw snapshot", "dimension", msg.Dimension, "error", aErr)
			if msg.Dimension == "availability" {
				result.Result = BuildAvailabilityResultJSON(snapshotJSON, nil)
			} else {
				result.Result = snapshotJSON
			}
		} else {
			result.Result = analyzed
		}

		if output != nil && output.HasIssue {
			annotations := BuildAnnotationsFromOutput(msg.Dimension, output)
			if len(annotations) > 0 {
				slog.Info("[Monitor] 准备生成标注截图", "dimension", msg.Dimension, "url", msg.URL, "annotations", len(annotations), "browser_ok", e.pageService.HasBrowser())
				annotatedData := e.pageService.CaptureAnnotatedScreenshot(ctx, msg.URL, annotations)
				if len(annotatedData) > 0 {
					result.AnnotatedScreenshotData = annotatedData
					slog.Info("[Monitor] 标注截图已生成", "dimension", msg.Dimension, "url", msg.URL, "size", len(annotatedData))
				} else {
					slog.Warn("[Monitor] 标注截图生成失败（返回空数据）", "dimension", msg.Dimension, "url", msg.URL)
				}
			} else {
				slog.Debug("[Monitor] 无标注信息可用", "dimension", msg.Dimension, "has_issue", output.HasIssue)
			}

			if msg.Dimension == "blacklink" {
				result.ExtraScreenshots = e.captureBlacklinkTargets(ctx, output)
			}
		}
	}

	return result
}

func (e *DBExecutor) captureBlacklinkTargets(ctx context.Context, output *analyzer.Output) []agent.ExtraScreenshot {
	if output == nil || output.DetailsJSON == "" {
		return nil
	}
	var details struct {
		BlacklinkMatches []struct {
			URL string `json:"url"`
		} `json:"blacklink_matches"`
		HiddenIframes []struct {
			Src string `json:"src"`
		} `json:"hidden_iframes"`
		JSRedirects []struct {
			Target string `json:"target"`
			Type   string `json:"type"`
		} `json:"js_redirects"`
		MetaRedirects []struct {
			URL string `json:"url"`
		} `json:"meta_redirects"`
	}
	if json.Unmarshal([]byte(output.DetailsJSON), &details) != nil {
		return nil
	}

	const maxTargets = 8
	seen := make(map[string]bool)
	var screenshots []agent.ExtraScreenshot

	captureOne := func(label, targetURL string) {
		if targetURL == "" || seen[targetURL] || len(screenshots) >= maxTargets {
			return
		}
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			return
		}
		seen[targetURL] = true
		data := e.pageService.CaptureSimpleScreenshot(ctx, targetURL)
		if len(data) > 0 {
			screenshots = append(screenshots, agent.ExtraScreenshot{
				Label: label,
				URL:   targetURL,
				Data:  data,
			})
			slog.Info("[Monitor] 暗链目标截图已生成", "label", label, "target_url", targetURL)
		}
	}

	for _, m := range details.BlacklinkMatches {
		captureOne("暗链目标", m.URL)
	}
	for _, r := range details.JSRedirects {
		captureOne("JS重定向目标", r.Target)
	}
	for _, iframe := range details.HiddenIframes {
		captureOne("隐藏iframe", iframe.Src)
	}
	for _, mr := range details.MetaRedirects {
		captureOne("Meta重定向目标", mr.URL)
	}

	return screenshots
}

func (e *DBExecutor) Close() error {
	if e.pageService != nil {
		e.pageService.Close()
	}
	return nil
}

func (e *DBExecutor) RefreshRules(ctx context.Context) {
	if e.analysis != nil {
		e.analysis.RefreshRules(ctx)
	}
}
