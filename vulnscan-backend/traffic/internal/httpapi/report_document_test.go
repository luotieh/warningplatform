package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestReportAPIAuthenticationPinnedVersionAndExport(t *testing.T) {
	st := store.NewMemoryStore()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("bad model request")
			return
		}
		reply := "OK"
		for _, m := range req.Messages {
			if m.Role != "user" || m.Content == "health" {
				continue
			}
			var input struct {
				Entries []struct {
					ID string `json:"id"`
				} `json:"selected_evidence"`
			}
			_ = json.Unmarshal([]byte(m.Content), &input)
			interpretations := []map[string]string{}
			for _, e := range input.Entries {
				interpretations = append(interpretations, map[string]string{"evidence_id": e.ID, "meaning": "提供当前通信的核验依据"})
			}
			raw, _ := json.Marshal(map[string]any{"target": "malicious_activity", "threat_type": "undetermined", "verdict": "insufficient", "stage": "undetermined", "probability": nil, "probability_reason": "需要结合业务背景判断", "supporting": []any{}, "opposing": []any{}, "alternatives": []any{}, "interpretations": interpretations, "gaps": []string{"补充业务归属"}, "actions": []any{}})
			reply = string(raw)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": reply}}}})
	}))
	defer model.Close()
	svc := service.Services{Store: st, LLM: &client.LLMClient{BaseURL: model.URL, Model: "api-fixture", HTTP: model.Client()}}
	ctx := context.Background()
	result, err := svc.ProcessLyEvent(ctx, map[string]any{"event_id": "api-report", "device_id": "node", "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "event_type": "scan", "rule_id": "r", "event_time": time.Now().Add(-time.Hour).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	id := result["deepsoc_event_id"].(string)
	if err = svc.RebuildAggregation(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = svc.RunAgentWorkflow(ctx, id); err != nil {
		t.Fatal(err)
	}
	summary := st.ListSummaries(id)[0]
	// A newer legacy record cannot replace the explicitly requested document.
	_, _ = st.AddSummary(domain.Summary{EventID: id, EventSummary: "legacy"})
	srv := New(config.Config{}, svc, nil)
	user, err := st.CreateUser(domain.User{UserID: "report-reader", Username: "report-reader", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.tokens["report-token"] = user.UserID
	base := fmt.Sprintf("/api/events/detail/%s/report", id)
	for _, tc := range []struct {
		path, token string
		status      int
		contains    string
	}{
		{base, "", 401, ""},
		{base + "?summary_id=0", "report-token", 400, "正整数"},
		{base + "?summary_id=garbage", "report-token", 400, "正整数"},
		{base, "report-token", 400, "legacy_report_without_evidence_document"},
		{base + fmt.Sprintf("?summary_id=%d", summary.ID), "report-token", 200, "evidence-report-1.0"},
		{base + "/export" + fmt.Sprintf("?summary_id=%d", summary.ID), "report-token", 200, ""},
		{"/api/events/detail/another-event/report" + fmt.Sprintf("?summary_id=%d", summary.ID), "report-token", 400, "report_not_found"},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
		if tc.status == 200 && strings.Contains(tc.path, "/export") {
			if !strings.HasPrefix(w.Body.String(), "PK") || !strings.Contains(w.Header().Get("Content-Type"), "wordprocessingml") || !strings.Contains(w.Header().Get("Content-Disposition"), ".docx") {
				t.Fatal("export is not a DOCX attachment")
			}
		}
	}
}
