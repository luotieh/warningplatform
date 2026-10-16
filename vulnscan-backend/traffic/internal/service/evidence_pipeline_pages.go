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

	"vulnscan-backend/evidence"
)

const pipelinePageItems = 100
const pipelinePageManifestBytes = 512 << 10
const pipelinePageDecodedBytes = 16 << 20
const pipelinePageCompressedBytes = 2 << 20
const pipelinePageTotalBytes = 64 << 20

// Optional index for new journals. Legacy manifests retain the full-load path.
// Each page carries only its own source dictionary and verifies that dictionary
// on restore. Publication remains atomic through the final journal manifest.
func (s Services) persistPipelinePages(ctx context.Context, m *pipelineJournalManifest, a EvidencePipelineAudit, items []evidence.UnifiedEvidence) error {
	defer pipelineMeasure(ctx, "audit_index")()
	m.TotalItems = len(items)
	total := 0
	for start := 0; start < len(items); start += pipelinePageItems {
		j := internPipelineSources(pipelineJournal{Audit: a, Evidence: ReportEvidenceBundle{Normalized: evidence.NormalizedEvidence{Items: items[start:min(start+pipelinePageItems, len(items))]}}})
		var buf bytes.Buffer
		bounded := &pipelineBoundedWriter{w: &buf, limit: pipelinePageCompressedBytes}
		gz := gzip.NewWriter(bounded)
		plain := &pipelineBoundedWriter{w: gz, limit: pipelinePageDecodedBytes}
		if err := json.NewEncoder(plain).Encode(j); err != nil {
			_ = gz.Close()
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		total += buf.Len()
		if total > pipelinePageTotalBytes {
			return fmt.Errorf("pipeline_page_index_budget_exceeded")
		}
		h := sha256.Sum256(buf.Bytes())
		m.PageHashes = append(m.PageHashes, hex.EncodeToString(h[:]))
		if err := putRecord(ctx, s.Store, "evidence_pipeline_page", fmt.Sprintf("%s:%d", m.Key, start/pipelinePageItems), m.EventID, buf.Bytes()); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(m)
	if len(raw) > pipelinePageManifestBytes {
		return fmt.Errorf("pipeline_page_manifest_budget_exceeded")
	}
	return nil
}

func (s Services) indexedPipelinePage(ctx context.Context, event, key string, offset, limit int) (ReportEvidencePage, bool, error) {
	fail := func(e string) (ReportEvidencePage, bool, error) {
		return ReportEvidencePage{}, true, fmt.Errorf("%s", e)
	}
	record, ok, err := s.Store.AggregateRecord(ctx, "evidence_pipeline", key)
	if err != nil || !ok {
		return fail("pipeline_journal_unavailable")
	}
	var m pipelineJournalManifest
	if len(record.Value) > pipelinePageManifestBytes || json.Unmarshal(record.Value, &m) != nil || m.EventID != event || m.Key != key || m.Encoding != "gzip-json-chunks-1" {
		return fail("pipeline_journal_manifest_invalid")
	}
	if len(m.PageHashes) == 0 {
		return ReportEvidencePage{}, false, nil
	}
	if m.TotalItems < 1 || len(m.PageHashes) != (m.TotalItems+pipelinePageItems-1)/pipelinePageItems || m.Parts < 1 || m.Parts > pipelineJournalCompressedBytes/pipelineJournalChunkBytes || m.Bytes < 1 || m.Bytes > pipelineJournalCompressedBytes {
		return fail("pipeline_page_index_invalid")
	}
	// Retain full compressed-journal integrity validation on every request. Only
	// decompression/JSON/source expansion is indexed; no unbounded cache is used.
	hash := sha256.New()
	compressed := 0
	for i := 0; i < m.Parts; i++ {
		r, found, e := s.Store.AggregateRecord(ctx, "evidence_pipeline_chunk", fmt.Sprintf("%s:%d", key, i))
		if e != nil || !found || len(r.Value) > pipelineJournalChunkBytes*2 {
			return fail("pipeline_journal_part_unavailable")
		}
		var part []byte
		if json.Unmarshal(r.Value, &part) != nil || len(part) > pipelineJournalChunkBytes {
			return fail("pipeline_journal_part_invalid")
		}
		compressed += len(part)
		if compressed > pipelineJournalCompressedBytes {
			return fail("pipeline_journal_budget_exceeded")
		}
		_, _ = hash.Write(part)
	}
	if compressed != m.Bytes || hex.EncodeToString(hash.Sum(nil)) != m.SHA256 {
		return fail("pipeline_journal_digest_invalid")
	}
	start := min(offset, m.TotalItems)
	end := min(start+limit, m.TotalItems)
	page := ReportEvidencePage{Offset: start, Total: m.TotalItems, Items: []evidence.UnifiedEvidence{}}
	// Even an empty page verifies the first page's event/audit binding.
	first, last := start/pipelinePageItems, (max(end-1, start))/pipelinePageItems
	if start == m.TotalItems {
		first, last = 0, 0
	}
	for index := first; index <= last; index++ {
		r, found, e := s.Store.AggregateRecord(ctx, "evidence_pipeline_page", fmt.Sprintf("%s:%d", key, index))
		if e != nil || !found || len(r.Value) > pipelinePageCompressedBytes*2 {
			return fail("pipeline_page_unavailable")
		}
		var data []byte
		if json.Unmarshal(r.Value, &data) != nil || len(data) > pipelinePageCompressedBytes {
			return fail("pipeline_page_invalid")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != m.PageHashes[index] {
			return fail("pipeline_page_digest_invalid")
		}
		gz, e := gzip.NewReader(bytes.NewReader(data))
		if e != nil {
			return fail("pipeline_page_gzip_invalid")
		}
		raw, e := io.ReadAll(io.LimitReader(gz, pipelinePageDecodedBytes+1))
		_ = gz.Close()
		if e != nil || len(raw) > pipelinePageDecodedBytes {
			return fail("pipeline_page_budget_exceeded")
		}
		var j pipelineJournal
		if json.Unmarshal(raw, &j) != nil || j.Audit.EventID != event || j.Audit.Key != key {
			return fail("pipeline_page_binding_invalid")
		}
		if err := restorePipelineSources(&j); err != nil {
			return ReportEvidencePage{}, true, err
		}
		items := j.Evidence.Normalized.Items
		if len(items) != min(pipelinePageItems, m.TotalItems-index*pipelinePageItems) {
			return fail("pipeline_page_count_invalid")
		}
		page.Audit = j.Audit
		if start < end {
			lo := max(start-index*pipelinePageItems, 0)
			hi := min(end-index*pipelinePageItems, len(items))
			page.Items = append(page.Items, items[lo:hi]...)
		}
	}
	return page, true, nil
}
