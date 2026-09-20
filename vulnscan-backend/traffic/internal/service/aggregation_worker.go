package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

func (s Services) convergeAggregation(ctx context.Context, id string, now time.Time) error {
	seg, ok, err := readSegment(ctx, s.Store, id)
	if err != nil || !ok {
		return err
	}
	return s.Store.AggregationTransaction(ctx, "group-"+seg.AggregateKey, func(tx store.Store) error {
		current, ok, err := readSegment(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok || current.Disabled || current.CanonicalID != id || now.Before(current.Last.Add(domain.ConvergenceIdleWindow)) {
			return nil
		}
		if _, ok = tx.UpdateEvent(id, map[string]any{"aggregation_closed": true, "last_seen_at": current.Last.Format(time.RFC3339Nano)}); !ok {
			return errors.New("save convergence failed")
		}
		ev, ok := tx.GetEvent(id)
		if !ok || asBool(decodeEventContext(ev.Context)["suppress_auto_analysis"]) {
			return nil
		}
		if r, exists, e := tx.AggregateRecord(ctx, "analysis_outbox", id); e != nil {
			return e
		} else if exists {
			var task map[string]any
			_ = json.Unmarshal(r.Value, &task)
			if task["kind"] == "final" && int64(toInt(task["version"])) == current.Version {
				return nil
			}
		}
		return putRecord(ctx, tx, "analysis_outbox", id, "pending", map[string]any{"kind": "final", "version": current.Version})
	})
}

// Workers acknowledge a task only after successful analysis. A lease makes
// process crashes recoverable and prevents multiple backend replicas running
// the same queued model request concurrently.
func (s Services) DrainAggregationAnalysis(ctx context.Context) error {
	if s.LLM == nil {
		return nil
	}
	records, err := s.Store.AggregateRecords(ctx, "analysis_outbox", "pending", 20)
	if err != nil {
		return err
	}
	for _, r := range records {
		var task map[string]any
		_ = json.Unmarshal(r.Value, &task)
		claimed := false
		err = s.Store.AggregationTransaction(ctx, "analysis-"+r.Key, func(tx store.Store) error {
			latest, ok, e := tx.AggregateRecord(ctx, "analysis_outbox", r.Key)
			if e != nil {
				return e
			}
			if !ok || latest.Group != "pending" {
				return nil
			}
			_ = json.Unmarshal(latest.Value, &task)
			if until := domain.ParseEventTime(task["lease_until"]); until.After(time.Now()) {
				return nil
			}
			task["lease_until"] = time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano)
			task["last_attempt"] = time.Now().UnixMilli()
			claimed = true
			return putRecord(ctx, tx, "analysis_outbox", r.Key, "pending", task)
		})
		if err != nil {
			return err
		}
		if !claimed {
			continue
		}
		seg, ok, err := readSegment(ctx, s.Store, r.Key)
		if err != nil {
			return err
		}
		ev, eventExists := s.Store.GetEvent(r.Key)
		if ok && !seg.Disabled && seg.CanonicalID == r.Key && eventExists && !asBool(decodeEventContext(ev.Context)["suppress_auto_analysis"]) {
			if task["kind"] == "final" {
				err = s.RunFinalAnalysis(ctx, r.Key)
			} else {
				err = s.RunAgentWorkflow(ctx, r.Key)
			}
		}
		runErr := err
		if err = s.Store.AggregationTransaction(ctx, "analysis-"+r.Key, func(tx store.Store) error {
			latest, ok, e := tx.AggregateRecord(ctx, "analysis_outbox", r.Key)
			if e != nil {
				return e
			}
			if !ok {
				return nil
			}
			var v map[string]any
			_ = json.Unmarshal(latest.Value, &v)
			// A convergence task may supersede an initial task while the model runs.
			if v["kind"] != task["kind"] || v["version"] != task["version"] {
				return nil
			}
			group := "done"
			v["lease_until"] = ""
			if runErr != nil {
				group = "pending"
				v["last_error"] = runErr.Error()
				v["lease_until"] = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
			}
			return putRecord(ctx, tx, "analysis_outbox", r.Key, group, v)
		}); err != nil {
			return err
		}
	}
	return nil
}
