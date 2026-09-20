package httpapi

import (
	"net/http"
	"strconv"
	"vulnscan-backend/traffic/internal/domain"
)

func (s *Server) getOccurrences(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	version, _ := strconv.ParseInt(r.URL.Query().Get("snapshot_version"), 10, 64)
	page, err := s.services.OccurrencesAt(r.Context(), r.PathValue("event_id"), r.URL.Query().Get("cursor"), r.PathValue("hit_id"), limit, version, r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: page})
}
