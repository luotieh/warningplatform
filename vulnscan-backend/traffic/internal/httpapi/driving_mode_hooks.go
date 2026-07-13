package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

const drivingModeStateKey = "driving_mode"

type drivingModeResponseRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *drivingModeResponseRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *drivingModeResponseRecorder) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *drivingModeResponseRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *drivingModeResponseRecorder) flush() {
	w.ResponseWriter.WriteHeader(w.statusCode())
	_, _ = w.ResponseWriter.Write(w.body.Bytes())
}

func (s *Server) drivingModeGetCompat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data": map[string]any{
			"enabled": true,
			"mode":    "auto",
		},
	})
}

func (s *Server) drivingModePut(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	_ = r.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data": map[string]any{
			"enabled": true,
			"mode":    "auto",
		},
	})
}

func (s *Server) withDrivingModeAutomation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(requestBody))

		rec := &drivingModeResponseRecorder{ResponseWriter: w}
		next(rec, r)

		if code := rec.statusCode(); code >= 200 && code < 300 {
			eventID, _ := drivingEventFromResponse(rec.body.Bytes())
			if eventID == "" {
				eventID, _ = drivingEventFromBytes(requestBody)
			}
			if eventID != "" {
				// 异步且脱离请求 ctx：同步跑会拖住响应 flush，且请求 ctx 在客户端
				// 断开时被取消，LLM 调用中途被杀会在报告页留下 context canceled
				// 假故障消息。失败详情由消息流/实时广播呈现，无需在此记日志。
				s.services.RunAgentWorkflowAsync(eventID)
			} else if shouldAutoDriveCreatedEvent(r, requestBody) {
				log.Printf("auto-analysis: automation skipped because event id was not found path=%s", r.URL.Path)
			}
		}

		rec.flush()
	}
}

func (s *Server) getDrivingMode(r *http.Request) (bool, error) {
	s.setMemoryState(drivingModeStateKey, true)
	return true, nil
}

func (s *Server) setDrivingMode(r *http.Request, enabled bool) error {
	s.setMemoryState(drivingModeStateKey, true)
	return nil
}

func (s *Server) getMemoryState(key string) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.states[key]
}

func (s *Server) setMemoryState(key string, value bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.states[key] = value
}

func drivingEventFromResponse(raw []byte) (string, string) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", ""
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", ""
	}
	if data, ok := env["data"].(map[string]any); ok {
		return drivingEventFromMap(data)
	}
	return drivingEventFromMap(env)
}

func drivingEventFromRequest(r *http.Request) (string, string) {
	if r == nil || r.Body == nil {
		return "", ""
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return "", ""
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return "", ""
	}
	return drivingEventFromMap(req)
}

func drivingEventFromBytes(body []byte) (string, string) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", ""
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return "", ""
	}
	return drivingEventFromMap(req)
}

func shouldAutoDriveCreatedEvent(r *http.Request, body []byte) bool {
	if r == nil {
		return false
	}
	var req map[string]any
	if len(bytes.TrimSpace(body)) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	if r.URL == nil {
		return false
	}
	switch r.URL.Path {
	case "/api/event/create", "/internal/event/push":
		return true
	default:
		return false
	}
}

func drivingEventFromMap(m map[string]any) (string, string) {
	if m == nil {
		return "", ""
	}
	eventID := firstString(m, "event_id", "eventId", "eventID", "deepsoc_event_id", "deepSOCEventID", "deepSocEventID", "id")
	if eventID == "" {
		if upstream, ok := m["upstream"].(map[string]any); ok {
			eventID, _ = drivingEventFromMap(upstream)
		}
	}
	title := firstString(m, "title", "event_name", "eventName", "message")
	return eventID, title
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
