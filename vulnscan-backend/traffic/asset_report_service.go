package traffic

import (
	"context"
	"fmt"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
)

// AssetReportService 资产 IP 月度总结的服务门面，供 HTTP handler 使用。
type AssetReportService struct {
	core service.Services
}

func NewAssetReportService(core service.Services) *AssetReportService {
	return &AssetReportService{core: core}
}

// GenerateMonthly 生成全部启用 IP 资产在 period（YYYY-MM）内的月度总结。
func (s *AssetReportService) GenerateMonthly(ctx context.Context, period string) ([]domain.AssetReportSummary, error) {
	if period == "" {
		period = time.Now().UTC().Format("2006-01")
	}
	return s.core.GenerateAssetMonthlySummaries(ctx, period)
}

// RunMonthlyAsync 创建异步月度总结任务并立即返回 job，进度由 goroutine 更新。
func (s *AssetReportService) RunMonthlyAsync(ctx context.Context, period string) (domain.AssetReportJob, error) {
	if period == "" {
		period = time.Now().UTC().Format("2006-01")
	}
	total := 0
	for _, a := range s.core.Store.ListAssets() {
		if a.AssetType == "ip" && a.Status == 1 {
			total++
		}
	}
	job, err := s.core.Store.CreateAssetReportJob(domain.AssetReportJob{
		Period:      period,
		Status:      "queued",
		TotalAssets: total,
	})
	if err != nil {
		return domain.AssetReportJob{}, err
	}
	go func() {
		ctx := context.Background()
		started := time.Now().UTC().Format(time.RFC3339)
		_, _ = s.core.Store.UpdateAssetReportJob(job.ID, map[string]any{
			"status":     "running",
			"started_at": started,
		})
		_, genErr := s.core.GenerateAssetMonthlySummariesWithProgress(ctx, period, func(done, total int) {
			_, _ = s.core.Store.UpdateAssetReportJob(job.ID, map[string]any{
				"status":           "running",
				"completed_assets": done,
				"total_assets":     total,
			})
		})
		finished := time.Now().UTC().Format(time.RFC3339)
		if genErr != nil {
			_, _ = s.core.Store.UpdateAssetReportJob(job.ID, map[string]any{
				"status":      "failed",
				"error":       genErr.Error(),
				"finished_at": finished,
			})
			return
		}
		_, _ = s.core.Store.UpdateAssetReportJob(job.ID, map[string]any{
			"status":      "completed",
			"finished_at": finished,
		})
	}()
	return job, nil
}

// GetJob 查询异步月度总结任务进度。
func (s *AssetReportService) GetJob(jobID string) (domain.AssetReportJob, error) {
	job, ok := s.core.Store.GetAssetReportJob(jobID)
	if !ok {
		return domain.AssetReportJob{}, fmt.Errorf("任务不存在: %s", jobID)
	}
	return job, nil
}

// GetMonthly 查询某资产指定月份的月度总结。
func (s *AssetReportService) GetMonthly(assetID string, period string) (domain.AssetReportSummary, bool) {
	return s.core.Store.GetAssetReportSummary(assetID, period)
}

// ListMonthly 列出某资产全部历史月度总结。
func (s *AssetReportService) ListMonthly(assetID string) []domain.AssetReportSummary {
	return s.core.Store.ListAssetReportSummaries(assetID)
}
