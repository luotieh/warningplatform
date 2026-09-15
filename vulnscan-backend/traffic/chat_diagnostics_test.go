package traffic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"vulnscan-backend/traffic/internal/client"
	trafficconfig "vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func TestEngineerSendUsesUpdatedModelAndReturnsUpstreamReason(t *testing.T) {
	var requestedModel, requestedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requestedModel, _ = body["model"].(string)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"message":"模型不存在，请检查配置", "code":"model_not_found"}}`))
	}))
	defer srv.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateEvent(domain.Event{EventID: "evt-test"}); err != nil {
		t.Fatal(err)
	}
	llm := &client.LLMClient{BaseURL: "http://unused.invalid", Model: "old"}
	chat := NewChatService(trafficservice.Services{LLM: llm, Store: st})
	chat.UpdateLLM(trafficconfig.LLMSettings{BaseURL: srv.URL + "/v1", Model: "configured", TimeoutSeconds: 5})
	h := &Handler{chat: chat}
	router := gin.New()
	router.POST("/send", h.EngineerChatSend)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/send", strings.NewReader(`{"event_id":"evt-test","message":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != 502 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if requestedModel != "configured" || requestedPath != "/v1/chat/completions" {
		t.Fatalf("model=%s path=%s", requestedModel, requestedPath)
	}
	for _, want := range []string{"模型不存在", "model=configured", srv.URL + "/v1/chat/completions", "status=400"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %s: %s", want, w.Body)
		}
	}
}
