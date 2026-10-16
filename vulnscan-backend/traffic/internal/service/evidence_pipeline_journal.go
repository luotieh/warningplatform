package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"vulnscan-backend/evidence"
)

const pipelineJournalChunkBytes = 512 << 10
const pipelineJournalDecodedBytes = 256 << 20
const pipelineJournalCompressedBytes = 16 << 20

type pipelineJournal struct {
	Audit       EvidencePipelineAudit                 `json:"audit"`
	Evidence    ReportEvidenceBundle                  `json:"evidence"`
	SourceSets  map[string][]string                   `json:"source_sets,omitempty"`
	BindingSets map[string][]evidence.PhaseOneBinding `json:"binding_sets,omitempty"`
}
type pipelineJournalManifest struct {
	PageHashes []string `json:"page_hashes,omitempty"`
	TotalItems int      `json:"total_items,omitempty"`
	EventID    string   `json:"event_id"`
	Key        string   `json:"key"`
	Encoding   string   `json:"encoding"`
	Parts      int      `json:"parts"`
	Bytes      int      `json:"compressed_bytes"`
	SHA256     string   `json:"sha256"`
}
type pipelineBoundedWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (w *pipelineBoundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.n {
		return 0, fmt.Errorf("pipeline_journal_budget_exceeded: written=%d limit=%d next=%d", w.n, w.limit, len(p))
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

// Stream into compressed, bounded chunks. Manifest is committed last, so a
// cancelled/failed write cannot expose a partial journal as a complete audit.
func (s Services) persistPipelineJournal(ctx context.Context, key, eventID string, j pipelineJournal) error {
	defer pipelineMeasure(ctx, "audit_storage")()
	// Full normalized instances are the canonical F/S audit. Avoid serializing
	// duplicate embeddings and raw payload copies; immutable snapshot/source IDs
	// and the semantic result journal bind those originals.
	b := j.Evidence
	b.FactChecks = nil
	b.SemanticChecks = nil
	b.Entries = append([]ReportEvidence(nil), b.Entries...)
	for i := range b.Entries {
		b.Entries[i].Finding = nil
		b.Entries[i].Unified = nil
		b.Entries[i].Semantic = nil
	}
	if b.PhaseOne != nil {
		p := *b.PhaseOne
		p.Facts = nil
		p.Materials.Records = nil
		b.PhaseOne = &p
	}
	j.Evidence = b
	j = internPipelineSources(j)
	var buf bytes.Buffer
	compressed := &pipelineBoundedWriter{w: &buf, limit: pipelineJournalCompressedBytes}
	gz := gzip.NewWriter(compressed)
	decoded := &pipelineBoundedWriter{w: gz, limit: pipelineJournalDecodedBytes}
	if err := json.NewEncoder(decoded).Encode(j); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	sum := sha256.Sum256(buf.Bytes())
	m := pipelineJournalManifest{EventID: eventID, Key: key, Encoding: "gzip-json-chunks-1", Bytes: buf.Len(), SHA256: hex.EncodeToString(sum[:])}
	for offset := 0; offset < buf.Len(); offset += pipelineJournalChunkBytes {
		end := min(offset+pipelineJournalChunkBytes, buf.Len())
		if err := putRecord(ctx, s.Store, "evidence_pipeline_chunk", fmt.Sprintf("%s:%d", key, m.Parts), eventID, buf.Bytes()[offset:end]); err != nil {
			return err
		}
		m.Parts++
	}
	if err := s.persistPipelinePages(ctx, &m, j.Audit, b.Normalized.Items); err != nil {
		return err
	}
	return putRecord(ctx, s.Store, "evidence_pipeline", key, eventID, m)
}
func (s Services) loadPipelineJournal(ctx context.Context, eventID, key string) (pipelineJournal, error) {
	var j pipelineJournal
	record, ok, err := s.Store.AggregateRecord(ctx, "evidence_pipeline", key)
	if err != nil || !ok {
		return j, fmt.Errorf("pipeline_journal_unavailable")
	}
	var m pipelineJournalManifest
	if len(record.Value) > pipelinePageManifestBytes || json.Unmarshal(record.Value, &m) != nil || m.EventID != eventID || m.Key != key || m.Encoding != "gzip-json-chunks-1" || m.Parts < 1 || m.Parts > pipelineJournalCompressedBytes/pipelineJournalChunkBytes || m.Bytes > pipelineJournalCompressedBytes {
		return j, fmt.Errorf("pipeline_journal_manifest_invalid")
	}
	var buf bytes.Buffer
	for i := 0; i < m.Parts; i++ {
		part, found, e := s.Store.AggregateRecord(ctx, "evidence_pipeline_chunk", fmt.Sprintf("%s:%d", key, i))
		if e != nil || !found || len(part.Value) > pipelineJournalChunkBytes*2 {
			return j, fmt.Errorf("pipeline_journal_part_unavailable")
		}
		var data []byte
		if json.Unmarshal(part.Value, &data) != nil || len(data) > pipelineJournalChunkBytes || buf.Len()+len(data) > pipelineJournalCompressedBytes {
			return j, fmt.Errorf("pipeline_journal_part_invalid")
		}
		buf.Write(data)
	}
	sum := sha256.Sum256(buf.Bytes())
	if buf.Len() != m.Bytes || hex.EncodeToString(sum[:]) != m.SHA256 {
		return j, fmt.Errorf("pipeline_journal_digest_invalid")
	}
	gz, e := gzip.NewReader(&buf)
	if e != nil {
		return j, e
	}
	defer gz.Close()
	limited := io.LimitReader(gz, pipelineJournalDecodedBytes+1)
	decoder := json.NewDecoder(limited)
	if e = decoder.Decode(&j); e != nil {
		return j, e
	}
	var extra any
	if e = decoder.Decode(&extra); e != io.EOF {
		return j, fmt.Errorf("pipeline_journal_trailing_or_oversized")
	}
	if j.Audit.EventID != eventID || j.Audit.Key != key {
		return j, fmt.Errorf("pipeline_journal_binding_invalid")
	}
	if err := restorePipelineSources(&j); err != nil {
		return j, err
	}
	return j, nil
}

type ReportEvidencePage struct {
	Audit  EvidencePipelineAudit      `json:"audit"`
	Offset int                        `json:"offset"`
	Total  int                        `json:"total"`
	Items  []evidence.UnifiedEvidence `json:"items"`
}

// The report supplies the audit key. Callers cannot substitute another event's
// journal or request an unbounded serialized result through this endpoint.
func (s Services) ReportEvidenceDetails(ctx context.Context, doc ReportDocument, offset, limit int) (ReportEvidencePage, error) {
	if doc.Evidence.Pipeline == nil {
		return ReportEvidencePage{}, fmt.Errorf("pipeline_audit_unavailable")
	}
	if offset < 0 || limit < 1 || limit > 100 {
		return ReportEvidencePage{}, fmt.Errorf("evidence_page_invalid")
	}
	if page, indexed, err := s.indexedPipelinePage(ctx, doc.EventID, doc.Evidence.Pipeline.Key, offset, limit); indexed || err != nil {
		return page, err
	}
	j, err := s.loadPipelineJournal(ctx, doc.EventID, doc.Evidence.Pipeline.Key)
	if err != nil {
		return ReportEvidencePage{}, err
	}
	n := len(j.Evidence.Normalized.Items)
	start := min(offset, n)
	end := min(start+limit, n)
	return ReportEvidencePage{Audit: j.Audit, Offset: start, Total: n, Items: j.Evidence.Normalized.Items[start:end]}, nil
}

// Report prose and model projection are retained exactly. Bulky source graphs,
// protocol payloads and all rule instances live in the independently bound audit.
func compactPipelineReport(doc ReportDocument) ReportDocument {
	b := doc.Evidence
	if b.Pipeline == nil {
		return doc
	}
	b.CurrentSourceIDs = nil
	b.FactChecks = nil
	b.SemanticChecks = nil
	b.Normalized.Items = nil
	if b.History != nil {
		h := *b.History
		h.Rows = nil
		h.FrozenSnapshots = nil
		b.History = &h
	}
	if b.PhaseOne != nil {
		p := *b.PhaseOne
		p.Materials = PhaseOneMaterials{}
		p.Facts = nil
		p.Result = compactPipelineJoint(p.Result)
		b.PhaseOne = &p
	}
	if b.Essence != nil {
		e := *b.Essence
		e.Trace = nil
		b.Essence = &e
	}
	selected := map[string]bool{}
	for _, id := range b.SelectedIDs {
		selected[id] = true
	}
	entries := []ReportEvidence{}
	for _, e := range b.Entries {
		if selected[e.ID] {
			e.SourceIDs = nil
			e.Dependencies = nil
			e.MaterialSourceIDs = nil
			e.Unified = nil
			e.Finding = nil
			e.Semantic = nil
			entries = append(entries, e)
		}
	}
	b.Entries = entries
	doc.Evidence = b
	if doc.Assessment.EvidenceRisk != nil {
		r := compactPipelineJoint(*doc.Assessment.EvidenceRisk)
		doc.Assessment.EvidenceRisk = &r
	}
	return doc
}

func compactPipelineJoint(r evidence.PhaseOneResult) evidence.PhaseOneResult {
	r.Units = append([]evidence.PhaseOneUnit(nil), r.Units...)
	for i := range r.Units {
		u := &r.Units[i]
		u.SourceIDs = nil
		u.IOCBindings = nil
		if u.Fact != nil {
			f := *u.Fact
			f.SourceIDs = nil
			f.Dependencies = nil
			u.Fact = &f
		}
	}
	return r
}
func pipelineJointModelProjection(r evidence.PhaseOneResult) map[string]any {
	compact := compactPipelineJoint(r)
	units := []map[string]any{}
	counts := map[string]int{}
	for _, u := range compact.Units {
		counts[u.Status]++
		if u.Status == "observed" && len(units) < 3 {
			units = append(units, pipelineJointUnitProjection(u))
		}
	}
	return map[string]any{"version": r.Version, "policy": r.Policy, "score": r.Score, "score_meaning": r.ScoreMeaning, "states": counts, "observed_units": units, "omitted_units": len(r.Units) - len(units), "details_location": "evidence_pipeline audit; omitted/missing units are not negative"}
}

// Intern repeated source/binding sets across rule instances. References are an
// internal wire encoding only and are expanded before any result is exposed.
func internPipelineSources(j pipelineJournal) pipelineJournal {
	j.SourceSets = map[string][]string{}
	j.BindingSets = map[string][]evidence.PhaseOneBinding{}
	apply := func(ids []string) []string {
		if len(ids) == 0 {
			return ids
		}
		key := digest(ids)
		j.SourceSets[key] = ids
		return []string{"$source_set:" + key}
	}
	walkPipelineSourceSets(&j, apply)
	if j.Evidence.PhaseOne != nil {
		p := *j.Evidence.PhaseOne
		p.Result.Units = append([]evidence.PhaseOneUnit(nil), p.Result.Units...)
		for i := range p.Result.Units {
			bindings := p.Result.Units[i].IOCBindings
			if len(bindings) == 0 {
				continue
			}
			key := digest(bindings)
			j.BindingSets[key] = bindings
			p.Result.Units[i].IOCBindings = []evidence.PhaseOneBinding{{Reason: "$binding_set:" + key}}
		}
		j.Evidence.PhaseOne = &p
	}
	return j
}
func restorePipelineSources(j *pipelineJournal) error {
	var failure error
	apply := func(ids []string) []string {
		if len(ids) == 1 && strings.HasPrefix(ids[0], "$source_set:") {
			key := strings.TrimPrefix(ids[0], "$source_set:")
			v, ok := j.SourceSets[key]
			if !ok || digest(v) != key {
				failure = fmt.Errorf("pipeline_source_set_invalid")
			}
			return v
		}
		return ids
	}
	walkPipelineSourceSets(j, apply)
	if j.Evidence.PhaseOne != nil {
		for i := range j.Evidence.PhaseOne.Result.Units {
			u := &j.Evidence.PhaseOne.Result.Units[i]
			if len(u.IOCBindings) == 1 && strings.HasPrefix(u.IOCBindings[0].Reason, "$binding_set:") {
				key := strings.TrimPrefix(u.IOCBindings[0].Reason, "$binding_set:")
				v, ok := j.BindingSets[key]
				if !ok || digest(v) != key {
					return fmt.Errorf("pipeline_binding_set_invalid")
				}
				u.IOCBindings = v
			}
		}
	}
	j.SourceSets = nil
	j.BindingSets = nil
	return failure
}
func walkPipelineSourceSets(j *pipelineJournal, apply func([]string) []string) {
	dependencies := func(v []evidence.Dependency) []evidence.Dependency {
		v = append([]evidence.Dependency(nil), v...)
		for i := range v {
			v[i].SourceIDs = apply(v[i].SourceIDs)
		}
		return v
	}
	b := j.Evidence
	b.Normalized.Items = append([]evidence.UnifiedEvidence(nil), b.Normalized.Items...)
	for i := range b.Normalized.Items {
		u := &b.Normalized.Items[i]
		u.SourceIDs = apply(u.SourceIDs)
		u.Dependencies = dependencies(u.Dependencies)
	}
	b.Entries = append([]ReportEvidence(nil), b.Entries...)
	for i := range b.Entries {
		e := &b.Entries[i]
		e.SourceIDs = apply(e.SourceIDs)
		e.Dependencies = dependencies(e.Dependencies)
		if e.MaterialSourceIDs != nil {
			m := map[string][]string{}
			for key, ids := range e.MaterialSourceIDs {
				m[key] = apply(ids)
			}
			e.MaterialSourceIDs = m
		}
	}
	if b.PhaseOne != nil {
		p := *b.PhaseOne
		p.Result.Units = append([]evidence.PhaseOneUnit(nil), p.Result.Units...)
		for i := range p.Result.Units {
			u := &p.Result.Units[i]
			u.SourceIDs = apply(u.SourceIDs)
			if u.Fact != nil {
				f := *u.Fact
				f.SourceIDs = apply(f.SourceIDs)
				f.Dependencies = dependencies(f.Dependencies)
				u.Fact = &f
			}
		}
		b.PhaseOne = &p
	}
	if b.Essence != nil {
		e := *b.Essence
		e.Trace = append([]ReportEssenceTrace(nil), e.Trace...)
		for i := range e.Trace {
			e.Trace[i].SourceIDs = apply(e.Trace[i].SourceIDs)
		}
		b.Essence = &e
	}
	j.Evidence = b
}
