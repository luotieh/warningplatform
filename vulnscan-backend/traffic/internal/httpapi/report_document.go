package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
)

func (s *Server) readReportDocument(w http.ResponseWriter, r *http.Request) (service.ReportDocument, bool) {
	if _, ok := s.currentUser(r); !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return service.ReportDocument{}, false
	}
	id := int64(0)
	if raw := r.URL.Query().Get("summary_id"); raw != "" {
		var err error
		id, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			writeJSON(w, 400, domain.APIResponse{Status: "error", Message: "summary_id必须为正整数"})
			return service.ReportDocument{}, false
		}
	}
	var doc service.ReportDocument
	var err error
	if r.URL.Path != "" && strings.HasSuffix(r.URL.Path, "/export") {
		doc, err = s.services.ReportDocumentForExport(r.Context(), r.PathValue("event_id"), id)
	} else {
		doc, err = s.services.ReportDocument(r.Context(), r.PathValue("event_id"), id)
	}
	if err != nil {
		writeJSON(w, 400, domain.APIResponse{Status: "error", Message: err.Error()})
		return doc, false
	}
	return doc, true
}
func (s *Server) getReportDocument(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.readReportDocument(w, r)
	if ok {
		writeJSON(w, 200, domain.APIResponse{Status: "success", Data: doc})
	}
}
func (s *Server) exportReportDocument(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.readReportDocument(w, r)
	if !ok {
		return
	}
	includeAppendix := false
	if raw := r.URL.Query().Get("include_appendix"); raw != "" {
		var err error
		includeAppendix, err = strconv.ParseBool(raw)
		if err != nil {
			writeJSON(w, 400, domain.APIResponse{Status: "error", Message: "include_appendix必须为布尔值"})
			return
		}
	}
	var data []byte
	var err error
	if includeAppendix {
		data, err = service.ExportEvidenceReportDOCXWithAppendix(doc)
	} else {
		data, err = service.ExportEvidenceReportDOCX(doc)
	}
	if err != nil {
		writeJSON(w, 500, domain.APIResponse{Status: "error", Message: "报告导出失败"})
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-report.docx"`)
	_, _ = w.Write(data)
}

func (s *Server) getReportEvidenceDetails(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.readReportDocument(w, r)
	if !ok {
		return
	}
	offset, limit := 0, 50
	for key, target := range map[string]*int{"offset": &offset, "limit": &limit} {
		if raw := r.URL.Query().Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				writeError(w, 400, "evidence_page_invalid")
				return
			}
			*target = n
		}
	}
	page, err := s.services.ReportEvidenceDetails(r.Context(), doc, offset, limit)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, domain.APIResponse{Status: "success", Data: page})
}
