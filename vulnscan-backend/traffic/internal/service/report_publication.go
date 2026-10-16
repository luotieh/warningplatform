package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/realtime"
	"vulnscan-backend/traffic/internal/store"
)

func reportErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A successful new document, its expert message, snapshot marker and list
// probability are committed together. Legacy readers/old save helpers are unchanged.
func (s Services) publishReportDocument(ctx context.Context, doc ReportDocument, round int, inputEvent domain.Event) (summary domain.Summary, err error) {
	if doc.Assessment.Probability == nil {
		return summary, fmt.Errorf("report_probability_required")
	}
	key, err := s.analysisEventLockKey(doc.EventID)
	if err != nil {
		return summary, err
	}
	if doc.Evidence.Pipeline != nil {
		if !doc.Evidence.Pipeline.Persisted {
			audit := *doc.Evidence.Pipeline
			audit.Persisted = true
			if e := s.persistPipelineJournal(ctx, audit.Key, doc.EventID, pipelineJournal{Audit: audit, Evidence: doc.Evidence}); e != nil {
				return summary, fmt.Errorf("pipeline_audit_not_persisted: %w", e)
			}
			doc.Evidence.Pipeline = &audit
		}
		doc = compactPipelineReport(doc)
	}
	doc.TechnicalAppendix = renderReportTechnicalAppendix(doc)
	var message domain.Message
	err = s.Store.AggregationTransaction(ctx, key, func(tx store.Store) error {
		event, ok := tx.GetEvent(doc.EventID)
		if !ok {
			return fmt.Errorf("report event disappeared")
		}
		if event.AnalysisVersion >= doc.AnalysisVersion {
			return fmt.Errorf("report_publication_superseded")
		}
		var e error
		summary, e = tx.AddSummary(domain.Summary{EventID: doc.EventID, RoundID: round, Version: doc.AnalysisVersion, Kind: doc.Kind, EventSummary: doc.Markdown})
		if e != nil {
			return e
		}
		if summary.ID <= 0 {
			return fmt.Errorf("report_summary_identity_missing")
		}
		doc.SummaryID = summary.ID
		if e = putRecord(ctx, tx, "report_document", reportDocumentKey(doc.EventID, summary.ID), doc.EventID, doc); e != nil {
			return e
		}
		message, e = tx.AddMessage(domain.Message{EventID: doc.EventID, MessageFrom: NormalizeMessageFrom(domain.RoleExpert), MessageType: "event_summary", MessageContent: StandardContent(llmExpertResponse(inputEvent, round, summary, doc.Markdown)), RoundID: round, MessageCategory: "agent", SenderType: SenderType(domain.RoleExpert)})
		if e != nil {
			return e
		}
		c := decodeEventContext(event.Context)
		c["report_published"], c["report_kind"], c["report_version"] = true, doc.Kind, doc.AnalysisVersion
		c["analysis_job_state"] = "idle"
		delete(c, "analysis_failure_reason")
		delete(c, "analysis_failed_at")
		c["ai_probability"] = *doc.Assessment.Probability
		c["report_summary_id"] = summary.ID
		if doc.Evidence.SnapshotVersion > 0 {
			seg, exists, e := readSegment(ctx, tx, doc.EventID)
			if e != nil {
				return e
			}
			if !exists {
				return fmt.Errorf("report event missing")
			}
			c["report_data_version"] = doc.Evidence.SnapshotVersion
			c["report_stale"] = seg.Version != doc.Evidence.SnapshotVersion || seg.CanonicalID != doc.EventID
			if e = putRecord(ctx, tx, "report_manifest", snapshotKey(doc.EventID, doc.Evidence.SnapshotVersion), doc.EventID, decodeEventContext(inputEvent.Context)["input_manifest"]); e != nil {
				return e
			}
		}
		raw, e := json.Marshal(c)
		if e != nil {
			return e
		}
		if _, ok := tx.UpdateEvent(doc.EventID, map[string]any{"context": string(raw), "event_status": "round_finished", "analysis_version": doc.AnalysisVersion, "last_analysis_at": time.Now().UTC().Format(time.RFC3339Nano)}); !ok {
			return fmt.Errorf("save report state failed")
		}
		return nil
	})
	if err == nil {
		realtime.BroadcastMessage(doc.EventID, message)
		_ = s.publish(context.Background(), "notifications.frontend."+doc.EventID+"."+domain.RoleExpert+".event_summary", doc.EventID, domain.RoleExpert, message)
	}
	return summary, err
}
