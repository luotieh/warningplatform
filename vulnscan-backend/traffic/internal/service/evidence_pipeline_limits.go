package service

import (
	"context"
	"time"
)

// Per-deployment limits, independent of statistical thresholds. Zero fields use
// bounded defaults. FeatureBytes accounts retained features, not a process RSS cap.
type EvidencePipelineLimits struct {
	HistoryFreezeWorkers                                           int
	PageRows                                                       int
	PageBytes, RowBytes, SnapshotBytes, FeatureBytes, HistoryBytes int64
	HistorySnapshots                                               int
	HistoryHits                                                    int64
	TotalTimeout, SnapshotTimeout, HistoryTimeout                  time.Duration
}
type pipelineLimitsKey struct{}

func defaultPipelineLimits() EvidencePipelineLimits {
	return EvidencePipelineLimits{HistoryFreezeWorkers: 4, PageRows: 500, PageBytes: snapshotPageBytes, RowBytes: snapshotRowBytes, SnapshotBytes: snapshotTotalBytes, FeatureBytes: snapshotFeatureBytes, HistoryBytes: snapshotTotalBytes, HistorySnapshots: 100, HistoryHits: 20000, TotalTimeout: 5 * time.Minute, SnapshotTimeout: 60 * time.Second, HistoryTimeout: 30 * time.Second}
}
func (s Services) pipelineLimits() EvidencePipelineLimits {
	d := defaultPipelineLimits()
	if s.EvidenceLimits == nil {
		return d
	}
	v := *s.EvidenceLimits
	if v.HistoryFreezeWorkers > 0 {
		d.HistoryFreezeWorkers = min(v.HistoryFreezeWorkers, 4)
	}
	if v.PageRows > 0 {
		d.PageRows = min(v.PageRows, 500)
	}
	if v.PageBytes > 0 {
		d.PageBytes = v.PageBytes
	}
	if v.RowBytes > 0 {
		d.RowBytes = min(v.RowBytes, d.PageBytes)
	}
	if v.SnapshotBytes > 0 {
		d.SnapshotBytes = v.SnapshotBytes
	}
	if v.FeatureBytes > 0 {
		d.FeatureBytes = v.FeatureBytes
	}
	if v.HistoryBytes > 0 {
		d.HistoryBytes = v.HistoryBytes
	}
	if v.HistorySnapshots > 0 {
		d.HistorySnapshots = v.HistorySnapshots
	}
	if v.HistoryHits > 0 {
		d.HistoryHits = v.HistoryHits
	}
	if v.TotalTimeout > 0 {
		d.TotalTimeout = v.TotalTimeout
	}
	if v.SnapshotTimeout > 0 {
		d.SnapshotTimeout = v.SnapshotTimeout
	}
	if v.HistoryTimeout > 0 {
		d.HistoryTimeout = v.HistoryTimeout
	}
	return d
}
func contextPipelineLimits(ctx context.Context) EvidencePipelineLimits {
	if v, ok := ctx.Value(pipelineLimitsKey{}).(EvidencePipelineLimits); ok {
		return v
	}
	return defaultPipelineLimits()
}
