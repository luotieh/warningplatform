package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
	"vulnscan-backend/traffic/internal/store"
)

var reportExecutionInflight sync.Map

const AnalysisKindPeriodic = "periodic"

func (s Services) setAnalysisJob(id, state, kind string, failure ...string) error {
	key, err := s.analysisEventLockKey(id)
	if err != nil {
		return err
	}
	err = s.Store.AggregationTransaction(context.Background(), key, func(tx store.Store) error {
		e, ok := tx.GetEvent(id)
		if !ok {
			return errors.New("event not found")
		}
		c := decodeEventContext(e.Context)
		previousState, previousReason := c["analysis_job_state"], c["analysis_failure_reason"]
		c["analysis_job_state"] = state
		if state == "failed" && len(failure) > 0 {
			reason := analysisFailureSummary(failure[0])
			c["analysis_failure_reason"] = reason
			if previousState != "failed" || previousReason != reason {
				c["analysis_failed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			}
		}
		if kind != "" {
			c["analysis_job_kind"] = kind
		}
		if state == "running" {
			c["analysis_started_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		}
		b, _ := json.Marshal(c)
		status := "failed"
		if state == "running" {
			status = "processing"
		}
		if _, ok = tx.UpdateEvent(id, map[string]any{"context": string(b), "event_status": status}); !ok {
			return errors.New("save analysis state failed")
		}
		return nil
	})
	realtime.BroadcastEventListUpdate(map[string]any{"event_id": id})
	return err
}

func (s Services) analysisEventLockKey(id string) (string, error) {
	seg, ok, err := readSegment(context.Background(), s.Store, id)
	if err != nil {
		return "", err
	}
	if ok {
		return "group-" + seg.AggregateKey, nil
	}
	return "group-" + id, nil
}

func (s Services) publishAnalysisState(id, kind string, version int, probability *int) error {
	key, err := s.analysisEventLockKey(id)
	if err != nil {
		return err
	}
	return s.Store.AggregationTransaction(context.Background(), key, func(tx store.Store) error {
		e, ok := tx.GetEvent(id)
		if !ok {
			return errors.New("event disappeared")
		}
		c := decodeEventContext(e.Context)
		c["report_published"], c["report_kind"], c["report_version"] = true, kind, version
		c["analysis_job_state"] = "idle"
		delete(c, "analysis_failure_reason")
		delete(c, "analysis_failed_at")
		if probability == nil {
			delete(c, "ai_probability")
		} else {
			c["ai_probability"] = *probability
		}
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, ok = tx.UpdateEvent(id, map[string]any{"context": string(b), "event_status": "round_finished", "analysis_version": version, "last_analysis_at": time.Now().UTC().Format(time.RFC3339Nano)}); !ok {
			return errors.New("save report state failed")
		}
		return nil
	})
}

// List hints describe the cause without exposing upstream URLs, credentials or payloads.
func analysisFailureSummary(raw string) string {
	t := strings.ToLower(raw)
	for _, rule := range []struct {
		needles []string
		text    string
	}{
		{[]string{"额度", "余额", "quota", "usage limit", "insufficient_quota"}, "模型额度不足，恢复额度后重试"},
		{[]string{"401", "403", "认证", "权限", "unauthorized", "forbidden"}, "模型认证或访问权限异常，请检查配置"},
		{[]string{"未配置", "not configured"}, "未配置可用模型，请检查配置"},
		{[]string{"timeout", "deadline exceeded", "超时"}, "模型或数据查询超时，请稍后重试"},
		{[]string{"预算", "budget", "context_length", "token limit"}, "证据或模型输入超过预算"},
		{[]string{"429", "rate limit", "限流"}, "模型请求被限流，请稍后重试"},
		{[]string{"校验", "report_", "invalid json"}, "模型报告未通过格式或证据校验"},
		{[]string{"保存", "写入", "persist"}, "报告保存失败，请检查存储服务"},
		{[]string{"503", "502", "connection", "不可用", "no available channel"}, "模型或依赖服务暂不可用，请稍后重试"},
	} {
		for _, needle := range rule.needles {
			if strings.Contains(t, needle) {
				return rule.text
			}
		}
	}
	return "报告分析失败，请查看后台日志定位原因"
}

func (s Services) finalReportCurrent(e domain.Event) bool {
	c := decodeEventContext(e.Context)
	if c["report_kind"] == AnalysisKindFinal {
		return toInt(c["report_data_version"]) >= toInt(c["data_version"])
	}
	// Reports saved before report_kind existed used version 2 for the final report.
	return e.AnalysisVersion == 2 && c["report_kind"] == nil && toInt(c["report_data_version"]) >= toInt(c["data_version"])
}

func (s Services) ScanPeriodicAnalysis(ctx context.Context) (int, error) {
	reader, ok := s.Store.(interface {
		ListPeriodicAnalysisDue(context.Context, time.Time) ([]domain.Event, error)
	})
	if !ok {
		return 0, nil
	}
	now := time.Now().UTC()
	events, err := reader.ListPeriodicAnalysisDue(ctx, now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, event := range events {
		if asBool(decodeEventContext(event.Context)["suppress_auto_analysis"]) {
			continue
		}
		err = s.Store.AggregationTransaction(ctx, "analysis-"+event.EventID, func(tx store.Store) error {
			e, exists := tx.GetEvent(event.EventID)
			if !exists || domain.IsConverged(e, now) || e.LastAnalysisAt == nil || now.Sub(*e.LastAnalysisAt) < 30*time.Minute {
				return nil
			}
			if decodeEventContext(e.Context)["analysis_job_state"] == "running" {
				return nil
			}
			r, exists, err := tx.AggregateRecord(ctx, "analysis_outbox", e.EventID)
			if err != nil {
				return err
			}
			if exists && r.Group == "pending" {
				return nil
			}
			if err = putRecord(ctx, tx, "analysis_outbox", e.EventID, "pending", map[string]any{"kind": AnalysisKindPeriodic, "version": toInt(decodeEventContext(e.Context)["data_version"]), "scheduled_at": now.Format(time.RFC3339Nano)}); err != nil {
				return err
			}
			c := decodeEventContext(e.Context)
			c["analysis_job_state"], c["analysis_job_kind"] = "queued", AnalysisKindPeriodic
			b, _ := json.Marshal(c)
			if _, ok := tx.UpdateEvent(e.EventID, map[string]any{"context": string(b)}); !ok {
				return errors.New("save queued analysis state failed")
			}
			n++
			return nil
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s Services) RunPeriodicAnalysis(ctx context.Context, id string) error {
	e, ok := s.Store.GetEvent(id)
	if !ok {
		return errors.New("event not found")
	}
	if domain.IsConverged(e, time.Now().UTC()) {
		return s.RunFinalAnalysis(ctx, id)
	}
	if e.AnalysisVersion == 0 {
		return s.RunAgentWorkflow(ctx, id)
	}
	if e.LastAnalysisAt != nil && time.Since(*e.LastAnalysisAt) < 30*time.Minute {
		return nil
	}
	return s.runAnalysis(ctx, id, AnalysisKindPeriodic, e.AnalysisVersion+1)
}
