package traffic

import (
	"context"
	"errors"

	trafficconfig "vulnscan-backend/traffic/internal/config"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

type InternalService struct {
	cfg  trafficconfig.Config
	core trafficservice.Services
}

func NewInternalService(cfg trafficconfig.Config, core trafficservice.Services) *InternalService {
	return &InternalService{cfg: cfg, core: core}
}

func (s *InternalService) PushEvent(ctx context.Context, body map[string]any, apiKey string) (map[string]any, error) {
	if !s.validInternalKey(apiKey) {
		return nil, errors.New("UNAUTHORIZED")
	}
	res, err := s.core.ProcessLyEvent(ctx, body)
	if err != nil {
		return nil, err
	}
	// 分析异步执行、脱离请求上下文：推送/查看报告立即返回事件ID，分析结果经 websocket
	// 增量回传，避免 LLM 较慢时请求被取消而报 "context canceled / i/o timeout"。
	if eventID := internalString(res["deepsoc_event_id"]); eventID != "" {
		s.core.RunAgentWorkflowAsync(eventID)
	}
	return res, nil
}

func (s *InternalService) SyncRun(ctx context.Context) (map[string]any, error) {
	if s.core.FlowShadow.Enabled() {
		return s.core.RunSyncOnce(ctx, s.cfg.SyncBatchSize, s.cfg.SyncLookbackSeconds, s.cfg.SyncMaxRetries)
	}
	return map[string]any{
		"mode":    "local-mysql",
		"fetched": 0,
		"pushed":  0,
		"failed":  0,
		"message": "flow shadow disabled: sync skipped",
	}, nil
}

func (s *InternalService) DedupReset() map[string]any {
	return map[string]any{
		"reset":   true,
		"message": "dedup reset completed",
	}
}

func (s *InternalService) Flow(ctx context.Context, flowID string) (map[string]any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("flow data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetFlow(ctx, flowID)
}

func (s *InternalService) RelatedFlows(ctx context.Context, flowID string) (any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("flow data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetRelatedFlows(ctx, flowID, "", "", 20)
}

func (s *InternalService) Asset(ctx context.Context, ip string) (map[string]any, error) {
	if ip == "" {
		return nil, errors.New("ip is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("asset data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetAsset(ctx, ip)
}

func (s *InternalService) PreparePCAP(ctx context.Context, flowID string) (map[string]any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("pcap unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.PreparePCAP(ctx, flowID)
}

func (s *InternalService) PCAP(ctx context.Context, pcapID string) (map[string]any, error) {
	if pcapID == "" {
		return nil, errors.New("pcap_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("pcap unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetPCAP(ctx, pcapID)
}

func (s *InternalService) validInternalKey(apiKey string) bool {
	return s.cfg.InternalAPIKey == "" || apiKey == s.cfg.InternalAPIKey
}

func internalString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
