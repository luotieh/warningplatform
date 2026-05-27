package sitemonitor

import (
	"context"
	"log/slog"
	"time"

	coreContract "vulnscan-backend/incident/core/core-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

// CrawlScreenshotUploader 爬虫截图上传函数签名：JPEG 数据 + 文件标识 → 存储 ID/URL
type CrawlScreenshotUploader func(ctx context.Context, jpegData []byte, name string) (string, error)

type ctxKeyCreatorID struct{}

// WithCreatorID 将操作者 ID 注入 context，供异步任务使用。
func WithCreatorID(ctx context.Context, uid string) context.Context {
	return context.WithValue(ctx, ctxKeyCreatorID{}, uid)
}

// CreatorIDFromContext 从 context 获取操作者 ID。
func CreatorIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyCreatorID{}).(string); ok {
		return v
	}
	return ""
}

type serviceMonitor struct {
	db                *db.DB
	nats              *NatsServiceImpl
	eventBridge       *MonitorEventBridge
	screenshotBaseURL string
	crawlUploader     CrawlScreenshotUploader
}

func NewServiceMonitor(database *db.DB, incidentSvc coreContract.ServiceCore) *serviceMonitor {
	session, _ := database.GetDBSession()
	bridge := NewMonitorEventBridge(session, incidentSvc)
	SetMonitorIssueNotifier(bridge.OnIssueDetected)
	return &serviceMonitor{db: database, eventBridge: bridge}
}

// SetCrawlScreenshotUploader 注入截图上传能力（IAM Storage）
func (s *serviceMonitor) SetCrawlScreenshotUploader(fn CrawlScreenshotUploader, baseURL string) {
	s.crawlUploader = fn
	s.screenshotBaseURL = baseURL
}

// CrawlScreenshotURL 返回截图下载地址
func (s *serviceMonitor) CrawlScreenshotURL(fileID string) string {
	if fileID == "" || s.screenshotBaseURL == "" {
		return ""
	}
	return s.screenshotBaseURL + "/" + fileID + "/content"
}

func (s *serviceMonitor) GetDB() *db.DB { return s.db }

func (s *serviceMonitor) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func paginateQuery(query *gorm.DB, index, size int) *gorm.DB {
	if size <= 0 {
		size = 20
	}
	offset := 0
	if index > 0 && size > 0 {
		offset = (index - 1) * size
	}
	return query.Offset(offset).Limit(size)
}

// ══ KV 同步辅助（3次指数退避） ══

func (s *serviceMonitor) retryKVSync(ctx context.Context, fn func() error, label string) {
	if s.nats == nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(200<<uint(attempt-1)) * time.Millisecond)
		}
		if err := fn(); err != nil {
			slog.Warn("[Monitor] KV同步失败", "label", label, "attempt", attempt+1, "error", err)
			continue
		}
		return
	}
	slog.Error("[Monitor] KV同步最终失败", "label", label)
}
