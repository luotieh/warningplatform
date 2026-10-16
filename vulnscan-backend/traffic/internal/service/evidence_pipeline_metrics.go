package service

import (
	"context"
	"time"
)

// These counters describe this execution, unlike the immutable source manifest
// whose loaded byte/page totals continue to describe a cached dataset.
type EvidencePipelineMetrics struct {
	StageUS                   map[string]int64 `json:"stage_us,omitempty"`
	StageMS                   map[string]int64 `json:"stage_ms"`
	CacheHits                 map[string]int   `json:"cache_hits"`
	SnapshotReadPages         int              `json:"snapshot_read_pages"`
	SnapshotReadBytes         int64            `json:"snapshot_read_bytes"`
	JSONDecodes               int64            `json:"json_decodes"`
	WireFrameDecodes          int64            `json:"wire_frame_decodes"`
	HTTPRequestParses         int64            `json:"http_request_parses"`
	DNSMessageParses          int64            `json:"dns_message_parses"`
	HistoryMetadataPages      int              `json:"history_metadata_pages"`
	HistoricalSnapshotLookups int              `json:"historical_snapshot_lookups"`
	HistoricalReadPages       int              `json:"historical_read_pages"`
	HistoricalReadBytes       int64            `json:"historical_read_bytes"`
	SemanticModelCalls        int              `json:"semantic_model_calls"`
	InputTokenCountKnown      bool             `json:"input_token_count_known"`
}

type pipelineMetricsKey struct{}

func pipelineMetrics(ctx context.Context) *EvidencePipelineMetrics {
	m, _ := ctx.Value(pipelineMetricsKey{}).(*EvidencePipelineMetrics)
	return m
}
func pipelineMeasure(ctx context.Context, stage string) func() {
	start := time.Now()
	return func() {
		if m := pipelineMetrics(ctx); m != nil {
			m.StageMS[stage] += time.Since(start).Milliseconds()
			if m.StageUS == nil {
				m.StageUS = map[string]int64{}
			}
			m.StageUS[stage] += time.Since(start).Microseconds()
		}
	}
}
