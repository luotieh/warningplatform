package sitemonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"vulnscan-backend/model"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gorm.io/gorm"
)

func (s *NatsServiceImpl) StartResultConsumer(ctx context.Context) error {
	if s.nats == nil || s.nats.JS == nil {
		return nil
	}
	resultStream := s.nats.Config.ResultStream
	if resultStream == "" {
		resultStream = "MONITOR_RESULTS"
	}
	cons, err := s.nats.JS.CreateOrUpdateConsumer(ctx, resultStream, jetstream.ConsumerConfig{
		Durable:       "backend-result-consumer",
		FilterSubject: "monitor.result",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		slog.Error("[NATS] create result consumer failed", "error", err)
		return err
	}
	go func() {
		slog.Info("[NATS] result consumer started")
		errCount := 0
		for {
			select {
			case <-ctx.Done():
				slog.Info("[NATS] result consumer stopped")
				return
			default:
			}
			msgs, err := cons.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				errCount++
				backoff := time.Duration(1<<min(errCount, 5)) * time.Second
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
				select {
				case <-ctx.Done():
					slog.Info("[NATS] result consumer stopped during backoff")
					return
				case <-time.After(backoff):
				}
				continue
			}
			errCount = 0
			for msg := range msgs.Messages() {
				s.handleAgentResult(msg)
			}
		}
	}()
	return nil
}

func (s *NatsServiceImpl) StartStatusSubscriber(_ context.Context) error {
	if s.nats == nil || s.nats.Conn == nil {
		return nil
	}
	_, err := s.nats.Conn.QueueSubscribe("monitor.agent.status", "backend-status", func(msg *nats.Msg) {
		var status model.MonitorAgentStatus
		if err := json.Unmarshal(msg.Data, &status); err != nil {
			slog.Warn("[NATS] Agent状态反序列化失败", "error", err, "raw", string(msg.Data[:min(len(msg.Data), 200)]))
			return
		}
		s.handleAgentStatus(status)
	})
	return err
}

func (s *NatsServiceImpl) handleAgentResult(msg jetstream.Msg) {
	var ar model.MonitorAgentResult
	if err := json.Unmarshal(msg.Data(), &ar); err != nil {
		slog.Error("[NATS] parse result failed", "error", err)
		_ = msg.Nak()
		return
	}

	session, err := s.db.GetDBSession()
	if err != nil {
		_ = msg.Nak()
		return
	}

	startedAt := parseTime(ar.StartedAt)
	finishedAt := parseTime(ar.FinishedAt)

	exec := model.MonitorExecution{}
	if err := session.Where("id = ?", ar.ExecutionID).First(&exec).Error; err != nil {
		slog.Error("[NATS] execution not found", "eid", ar.ExecutionID)
		_ = msg.Ack()
		return
	}

	if exec.Status == "success" || exec.Status == "failed" {
		canOverride := exec.Status == "failed" && exec.ReapedAt != nil && ar.Status == "success"
		if !canOverride {
			slog.Debug("[NATS] execution already in terminal state, skipping",
				"eid", ar.ExecutionID, "status", exec.Status)
			_ = msg.Ack()
			return
		}
		slog.Info("[NATS] overriding reaper-set failure with Agent success",
			"eid", ar.ExecutionID, "reaped_at", exec.ReapedAt)
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

		switch ar.Dimension {
		case "sensitive_word":
			var r model.MonitorSensitiveWordResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				slog.Error("[NATS] parse sensitive_word result failed",
					"error", err, "eid", ar.ExecutionID)
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if err := s.saveSensitiveWordResult(tx, ar.ExecutionID, ar.TaskID, &r); err != nil {
					return fmt.Errorf("save word detail: %w", err)
				}
			}
		case "sensitive_file":
			var r model.MonitorSensitiveFileResult
			if err := json.Unmarshal([]byte(ar.Result), &r); err != nil {
				slog.Error("[NATS] parse sensitive_file result failed",
					"error", err, "eid", ar.ExecutionID)
				exec.Error = fmt.Sprintf("结果解析失败: %v", err)
				exec.HasIssue = true
			} else {
				exec.HasIssue = r.HasHit
				if r.Error != "" {
					exec.Error = r.Error
				}
				if err := s.saveSensitiveFileResult(tx, ar.ExecutionID, ar.TaskID, &r); err != nil {
					return fmt.Errorf("save file detail: %w", err)
				}
			}
		case "tamper":
			var tr model.MonitorTamperResult
			if err := json.Unmarshal([]byte(ar.Result), &tr); err != nil {
				slog.Warn("[NATS] parse tamper result failed", "error", err, "eid", ar.ExecutionID)
				exec.HasIssue = jsonBool(ar.Result, "tampered")
			} else {
				exec.HasIssue = tr.Tampered
				if tr.BaselineUpdate != nil {
					if err := s.saveBaselineFromResult(tx, ar.ExecutionID, ar.URL, ar.AgentID, tr.BaselineUpdate); err != nil {
						return fmt.Errorf("save baseline: %w", err)
					}
				}
			}
		case "blacklink":
			exec.HasIssue = jsonBool(ar.Result, "has_black")
		case "availability":
			exec.HasIssue = !jsonBool(ar.Result, "available")
		case "domain_hijack":
			exec.HasIssue = jsonBool(ar.Result, "hijacked")
		}

		if exec.HasIssue {
			exec.Disposition = model.MonitorDispositionPending
		} else {
			exec.Disposition = model.MonitorDispositionValid
		}

		return tx.Save(&exec).Error
	})

	if txErr != nil {
		slog.Error("[NATS] save result tx failed", "error", txErr, "eid", ar.ExecutionID)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
	slog.Info("[NATS] result processed", "eid", ar.ExecutionID, "dim", ar.Dimension, "status", ar.Status)
}

func (s *NatsServiceImpl) handleAgentStatus(status model.MonitorAgentStatus) {
	session, err := s.db.GetDBSession()
	if err != nil {
		slog.Warn("[NATS] Agent状态处理失败: DB session error", "error", err)
		return
	}

	var agent model.MonitorAgent
	agent.UUID = status.UUID
	agent.ID = status.UUID
	if err := session.Where("uuid = ?", status.UUID).
		FirstOrCreate(&agent).Error; err != nil {
		slog.Warn("[NATS] Agent upsert失败", "uuid", status.UUID, "error", err)
		return
	}

	now := time.Now()
	if err := session.Model(&agent).Updates(map[string]any{
		"status":         "online",
		"version":        status.Version,
		"mac_address":    status.MacAddress,
		"ip_address":     status.IPAddress,
		"running_tasks":  status.RunningTasks,
		"queued_tasks":   status.QueuedTasks,
		"max_concurrent": status.MaxConcurrent,
		"cpu_usage":      status.CPUUsage,
		"memory_usage":   status.MemoryUsage,
		"max_queue":      status.MaxQueue,
		"last_seen_at":   &now,
	}).Error; err != nil {
		slog.Warn("[NATS] Agent状态更新失败", "uuid", status.UUID, "error", err)
	}
}
