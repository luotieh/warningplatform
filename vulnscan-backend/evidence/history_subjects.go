package evidence

import (
	"fmt"
	"sort"
)

// HistorySubject is a source-bound current IOC and its separately retrieved
// history. It never changes the legacy single-history contract for other facts.
type HistorySubject struct {
	IOCType          string       `json:"ioc_type"`
	IOCValue         string       `json:"ioc_value"`
	CurrentSourceIDs []string     `json:"current_source_ids"`
	History          *HistoryData `json:"history"`
}

// ValidateHistorySubjects rejects ambiguity rather than selecting one IOC at
// a shared endpoint. The adapter also validates the actual saved IOC fields.
func ValidateHistorySubjects(in *Input, hits map[string]Hit) error {
	seen := map[string]bool{}
	for _, s := range in.PlatformHistorySubjects {
		key := s.IOCType + "\x00" + s.IOCValue
		if (s.IOCType != "ip" && s.IOCType != "domain" && s.IOCType != "url") || s.IOCValue == "" || seen[key] || len(s.CurrentSourceIDs) == 0 || s.History == nil || s.History.IOC != s.IOCValue || in.Window == nil {
			return fmt.Errorf("invalid_history_subject_identity")
		}
		seen[key] = true
		ids := map[string]bool{}
		for _, id := range s.CurrentSourceIDs {
			h, ok := hits[id]
			if !ok || ids[id] || h.Scope != in.Scope || h.OccurredAt.IsZero() || h.OccurredAt.Before(in.Window.Start) || !h.OccurredAt.Before(in.Window.End) {
				return fmt.Errorf("history_subject_current_source_mismatch")
			}
			ids[id] = true
		}
		for _, row := range s.History.Events {
			if row.IOCType != s.IOCType || row.IOC != s.IOCValue {
				return fmt.Errorf("history_subject_event_ioc_mismatch")
			}
		}
	}
	return nil
}

func (e *Engine) historySubjectFindings(g *observations, id FactID) ([]Finding, []Execution) {
	subjects := append([]HistorySubject(nil), g.input.PlatformHistorySubjects...)
	sort.Slice(subjects, func(i, j int) bool {
		return subjects[i].IOCType+"\x00"+subjects[i].IOCValue < subjects[j].IOCType+"\x00"+subjects[j].IOCValue
	})
	findings, executions := []Finding{}, []Execution{}
	for _, s := range subjects {
		in := *g.input
		in.PlatformHistory, in.History = s.History, s.History
		local := observations{scope: g.scope, request: g.request, complete: g.complete, input: &in}
		wanted := map[string]bool{}
		for _, id := range s.CurrentSourceIDs {
			wanted[id] = true
		}
		for _, h := range g.hits {
			if wanted[h.ID] {
				local.hits = append(local.hits, h)
				local.sourceIDs = append(local.sourceIDs, h.ID)
			}
		}
		sort.Strings(local.sourceIDs)
		var f Finding
		if id == "F_IOC_NOVELTY" {
			f = verifiedPriorIOCOccurrence(s, &local)
		} else {
			f = e.evaluateFactSafely(id, &local)
			f.ObservationKind = "event_occurrence"
		}
		f.IOCType, f.IOCValue = s.IOCType, s.IOCValue
		f.SnapshotVersion = g.request.SnapshotVersion
		status := "skipped"
		if f.Eligibility == "eligible" || f.ReasonCode == IncompleteNegative {
			status = "executed"
		}
		if f.ReasonCode == "rule_execution_error" {
			status = "execution_error"
		}
		findings = append(findings, f)
		executions = append(executions, Execution{FactID: f.FactID, Scope: f.Scope, IOCType: f.IOCType, IOCValue: f.IOCValue, ObservationKind: f.ObservationKind, Status: status, ReasonCode: f.ReasonCode})
	}
	return findings, executions
}
