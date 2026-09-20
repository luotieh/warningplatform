package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/lyserver"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/socketio"
)

type Server struct {
	cfg       config.Config
	services  service.Services
	mux       *http.ServeMux
	tokens    map[string]string
	ly        *lyserver.Service
	socketHub *socketio.Hub
	stateMu   sync.RWMutex
	states    map[string]bool
}

// New 构造独立模式 HTTP 服务；db 为共享 MySQL 连接池（可为 nil，
// 此时 /d/* LY 兼容接口降级为未启用）。
func New(cfg config.Config, services service.Services, db *sql.DB) *Server {
	s := &Server{cfg: cfg, services: services, mux: http.NewServeMux(), tokens: map[string]string{}, ly: lyserver.New(db), socketHub: socketio.NewHub(), states: map[string]bool{}}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return withCORS(s.mux)
}

func (s *Server) routes() {

	s.mux.HandleFunc("/socket.io/", s.socketHub.ServeHTTP)
	s.mux.HandleFunc("/socket.io", s.socketHub.ServeHTTP)
	s.mux.HandleFunc("/api/socket.io/", s.socketHub.ServeHTTP)
	s.mux.HandleFunc("/api/socket.io", s.socketHub.ServeHTTP)
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("GET /health/llm", s.llmHealth)
	s.mux.HandleFunc("GET /api/version", s.version)
	s.mux.HandleFunc("GET /api/llm/health", s.llmHealth)
	s.mux.HandleFunc("POST /api/llm/health", s.llmHealthTest)
	s.mux.HandleFunc("GET /api/llm/config", s.llmConfig)
	s.mux.HandleFunc("POST /api/llm/config", s.llmConfig)
	s.mux.HandleFunc("PUT /api/llm/config", s.llmConfig)
	s.mux.HandleFunc("GET /api/store/config", s.storeConfig)
	s.mux.HandleFunc("POST /api/store/config", s.storeConfig)
	s.mux.HandleFunc("PUT /api/store/config", s.storeConfig)
	s.mux.HandleFunc("POST /api/store/config/test", s.storeConfigTest)

	s.mux.HandleFunc("POST /internal/event/push", s.withDrivingModeAutomation(s.internalEventPush))
	s.mux.HandleFunc("POST /internal/sync:run", s.internalSyncRun)
	s.mux.HandleFunc("POST /internal/admin/dedup/reset", s.internalDedupReset)
	s.mux.HandleFunc("GET /internal/flows/{flow_id}", s.internalGetFlow)
	s.mux.HandleFunc("GET /internal/flows/{flow_id}/related", s.internalRelatedFlows)
	s.mux.HandleFunc("GET /internal/assets/{ip}", s.internalAsset)
	s.mux.HandleFunc("POST /internal/flows/{flow_id}/pcap:prepare", s.internalPreparePCAP)
	s.mux.HandleFunc("GET /internal/pcaps/{pcap_id}", s.internalGetPCAP)

	s.mux.HandleFunc("POST /api/auth/login", s.login)
	s.mux.HandleFunc("POST /api/auth/logout", s.ok)
	s.mux.HandleFunc("GET /api/auth/me", s.me)
	s.mux.HandleFunc("GET /api/auth/check-auth", s.checkAuth)
	s.mux.HandleFunc("POST /api/auth/init-admin", s.initAdmin)
	s.mux.HandleFunc("POST /api/auth/create-user", s.createUser)
	s.mux.HandleFunc("POST /api/auth/change-password", s.changePassword)

	s.mux.HandleFunc("POST /api/event/create", s.withDrivingModeAutomation(s.createEvent))
	s.mux.HandleFunc("GET /api/event/list", s.listEvents)
	s.mux.HandleFunc("GET /api/event/{event_id}", s.getEvent)
	s.mux.HandleFunc("GET /api/event/{event_id}/messages", s.getMessages)
	s.mux.HandleFunc("GET /api/event/{event_id}/tasks", s.getTasks)
	s.mux.HandleFunc("GET /api/event/{event_id}/actions", s.getActions)
	s.mux.HandleFunc("GET /api/event/{event_id}/commands", s.getCommands)
	s.mux.HandleFunc("GET /api/event/{event_id}/stats", s.getStats)
	s.mux.HandleFunc("GET /api/event/{event_id}/summaries", s.getSummaries)
	s.mux.HandleFunc("POST /api/event/send_message/{event_id}", s.withNewMessageBroadcast(s.sendEventMessage))
	s.mux.HandleFunc("GET /api/event/{event_id}/executions", s.getExecutions)
	s.mux.HandleFunc("POST /api/event/{event_id}/execution/{execution_id}/complete", s.withExecutionUpdateBroadcast(s.completeExecution))
	s.mux.HandleFunc("GET /api/event/{event_id}/hierarchy", s.getHierarchy)
	s.mux.HandleFunc("POST /api/events/create", s.withDrivingModeAutomation(s.createEvent))
	s.mux.HandleFunc("GET /api/events/list", s.listEvents)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}", s.getEvent)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/messages", s.getMessages)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/tasks", s.getTasks)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/actions", s.getActions)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/commands", s.getCommands)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/stats", s.getStats)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/occurrences", s.getOccurrences)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/occurrences/{hit_id}", s.getOccurrences)
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/summaries", s.getSummaries)
	s.mux.HandleFunc("POST /api/events/detail/{event_id}/messages", s.withNewMessageBroadcast(s.sendEventMessage))
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/executions", s.getExecutions)
	s.mux.HandleFunc("POST /api/events/detail/{event_id}/executions/{execution_id}/complete", s.withExecutionUpdateBroadcast(s.completeExecution))
	s.mux.HandleFunc("GET /api/events/detail/{event_id}/hierarchy", s.getHierarchy)

	s.mux.HandleFunc("GET /api/user/list", s.listUsers)
	s.mux.HandleFunc("POST /api/user", s.createUser)
	s.mux.HandleFunc("GET /api/user/{user_id}", s.getUser)
	s.mux.HandleFunc("PUT /api/user/{user_id}", s.updateUser)
	s.mux.HandleFunc("DELETE /api/user/{user_id}", s.deleteUser)
	s.mux.HandleFunc("PUT /api/user/{user_id}/password", s.updateUserPassword)

	s.mux.HandleFunc("GET /api/prompt/list", s.promptList)
	s.mux.HandleFunc("GET /api/prompt/{role}", s.promptGet)
	s.mux.HandleFunc("PUT /api/prompt/{role}", s.ok)
	s.mux.HandleFunc("GET /api/prompt/background/{name}", s.promptBackgroundGet)
	s.mux.HandleFunc("PUT /api/prompt/background/{name}", s.ok)

	s.mux.HandleFunc("GET /api/state/driving-mode", s.drivingModeGetCompat)
	s.mux.HandleFunc("PUT /api/state/driving-mode", s.drivingModePut)

	s.mux.HandleFunc("POST /api/engineer-chat/send", s.withNewMessageBroadcast(s.engineerChatSend))
	s.mux.HandleFunc("GET /api/engineer-chat/history", s.engineerChatHistory)
	s.mux.HandleFunc("POST /api/engineer-chat/new-session", s.engineerNewSession)
	s.mux.HandleFunc("GET /api/engineer-chat/status", s.engineerStatus)

	s.mux.HandleFunc("POST /api/report/global", s.reportGlobal)

	s.mux.HandleFunc("POST /d/auth", s.ly.Auth)
	s.mux.HandleFunc("GET /d/sctl", s.ly.Status)
	s.mux.HandleFunc("GET /d/config", s.ly.GetConfig)
	s.mux.HandleFunc("POST /d/config", s.ly.SetConfig)
	s.mux.HandleFunc("GET /d/mo", s.ly.GetMO)
	s.mux.HandleFunc("POST /d/mo", s.ly.SetMO)
	s.mux.HandleFunc("GET /d/bwlist", s.ly.GetBWList)
	s.mux.HandleFunc("POST /d/bwlist", s.ly.SetBWList)

	s.mux.HandleFunc("GET /d/event", s.ly.Event)
	s.mux.HandleFunc("GET /d/feature", s.ly.Feature)
	s.mux.HandleFunc("GET /d/topn", s.ly.TopN)
	s.mux.HandleFunc("GET /d/evidence", s.ly.Evidence)
	s.mux.HandleFunc("GET /d/rules", s.ly.Rules)
	// 规则读取路径配置（查看/保存）。RulesConfig 内部按方法区分 GET/POST。
	// 未注册时会落到下面的 /d/ 兜底代理，导致保存路径返回 404。
	s.mux.HandleFunc("GET /d/rules/config", s.ly.RulesConfig)
	s.mux.HandleFunc("POST /d/rules/config", s.ly.RulesConfig)

	s.mux.HandleFunc("/d/", s.flowShadowProxy)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "ok", "service": "traffic-go", "store_backend": s.cfg.StoreBackend, "mq_backend": s.cfg.MQBackend})
}

func (s *Server) llmHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.HTTPTimeout)
	defer cancel()
	result := s.services.LLM.HealthCheck(ctx)
	status := http.StatusOK
	if !result.Configured || !result.OK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, domain.APIResponse{Status: statusText(result.OK), Data: result})
}

// llmHealthTest 与 Gin 路径的 LLMHealthTest 对等：以请求体表单值（空字段回退
// 已保存配置）做连通性探测 + 测试对话。限时由探测客户端自身的超时负责，
// 不再包一层 server 级超时，避免截断合法的慢速 LLM 响应。
func (s *Server) llmHealthTest(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	result := s.services.LLM.WithOverrides(
		asString(body["base_url"]),
		asString(body["model"]),
		asString(body["api_key"]),
		intValue(body["timeout_seconds"]),
	).HealthTest(r.Context())
	status := http.StatusOK
	if !result.OK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, domain.APIResponse{Status: statusText(result.OK), Data: result})
}

func (s *Server) llmConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: config.SettingsFromConfig(s.cfg)})
	case http.MethodPost, http.MethodPut:
		var body map[string]any
		if !decodeJSON(w, r, &body) {
			return
		}
		settings := config.SettingsFromConfig(s.cfg)
		if v := strings.TrimSpace(asString(body["base_url"])); v != "" {
			settings.BaseURL = v
		}
		if _, ok := body["base_url"]; ok && strings.TrimSpace(asString(body["base_url"])) == "" {
			settings.BaseURL = ""
		}
		if v := strings.TrimSpace(asString(body["model"])); v != "" {
			settings.Model = v
		}
		if timeout := intValue(body["timeout_seconds"]); timeout > 0 {
			settings.TimeoutSeconds = timeout
		}
		apiKey := strings.TrimSpace(asString(body["api_key"]))
		updateAPIKey := apiKey != ""
		if updateAPIKey {
			settings.APIKey = apiKey
		}
		updated, err := config.WriteTrafficLLMSettings(settings, updateAPIKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.cfg.LLMBaseURL = updated.BaseURL
		s.cfg.LLMAPIKey = updated.APIKey
		s.cfg.LLMModel = updated.Model
		s.cfg.LLMTimeout = time.Duration(updated.TimeoutSeconds) * time.Second
		s.services.LLM.BaseURL = updated.BaseURL
		s.services.LLM.APIKey = updated.APIKey
		s.services.LLM.Model = updated.Model
		s.services.LLM.HTTP = &http.Client{Timeout: s.cfg.LLMTimeout}
		writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "LLM配置已保存", Data: config.SettingsFromConfig(s.cfg)})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) storeConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: config.SettingsFromStoreConfig(s.cfg)})
	case http.MethodPost, http.MethodPut:
		var body map[string]any
		if !decodeJSON(w, r, &body) {
			return
		}
		settings := config.SettingsFromStoreConfig(s.cfg)
		if v := strings.TrimSpace(asString(body["store_backend"])); v != "" {
			settings.StoreBackend = v
		}
		if v := strings.TrimSpace(asString(body["host"])); v != "" {
			settings.Host = v
		}
		if port := intValue(body["port"]); port > 0 {
			settings.Port = port
		}
		if v := strings.TrimSpace(asString(body["user"])); v != "" {
			settings.User = v
		}
		if v := strings.TrimSpace(asString(body["db_name"])); v != "" {
			settings.DBName = v
		}
		if v, ok := body["auto_migrate"]; ok {
			settings.AutoMigrate = boolValue(v)
		}
		if wait := intValue(body["db_wait_seconds"]); wait > 0 {
			settings.DBWaitSeconds = wait
		}
		password := strings.TrimSpace(asString(body["password"]))
		updatePassword := password != ""
		if updatePassword {
			settings.Password = password
		}
		updated, err := config.WriteTrafficStoreSettings(settings, updatePassword)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.cfg.StoreBackend = updated.StoreBackend
		s.cfg.DatabaseURL = config.BuildStoreDSN(updated)
		s.cfg.AutoMigrate = updated.AutoMigrate
		s.cfg.DBWaitSeconds = updated.DBWaitSeconds
		writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "MySQL配置已保存，存储后端变更需重启后生效", Data: config.SettingsFromStoreConfig(s.cfg)})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) storeConfigTest(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	settings := config.StoreSettings{StoreBackend: "mysql"}
	if v := strings.TrimSpace(asString(body["host"])); v != "" {
		settings.Host = v
	}
	if port := intValue(body["port"]); port > 0 {
		settings.Port = port
	}
	if v := strings.TrimSpace(asString(body["user"])); v != "" {
		settings.User = v
	}
	if v := strings.TrimSpace(asString(body["password"])); v != "" {
		settings.Password = v
	}
	if v := strings.TrimSpace(asString(body["db_name"])); v != "" {
		settings.DBName = v
	}
	result := config.TestStoreSettings(settings)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, domain.APIResponse{Status: statusText(result.OK), Data: result})
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true") || x == "1"
	}
	return false
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": "0.3.0-db-mq", "name": "traffic-go"})
}

func (s *Server) internalEventPush(w http.ResponseWriter, r *http.Request) {
	if !s.requireInternalKey(w, r) {
		return
	}
	var ly map[string]any
	if !decodeJSON(w, r, &ly) {
		return
	}
	res, err := s.services.ProcessLyEvent(r.Context(), ly)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) internalSyncRun(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"result": "ok",
		"data": map[string]any{
			"mode":    "local-postgres",
			"fetched": 0,
			"pushed":  0,
			"failed":  0,
			"message": "flow shadow not available: sync skipped",
		},
	})
}

func (s *Server) internalGetFlow(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("flow_id") == "" {
		writeError(w, http.StatusBadRequest, "flow_id不能为空")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "流量数据源不可用")
}

func (s *Server) internalRelatedFlows(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("flow_id") == "" {
		writeError(w, http.StatusBadRequest, "flow_id不能为空")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "流量数据源不可用")
}

func (s *Server) internalAsset(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("ip") == "" {
		writeError(w, http.StatusBadRequest, "ip不能为空")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "资产数据源不可用")
}

func (s *Server) internalPreparePCAP(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("flow_id") == "" {
		writeError(w, http.StatusBadRequest, "flow_id不能为空")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "PCAP 数据源不可用")
}

func (s *Server) internalGetPCAP(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("pcap_id") == "" {
		writeError(w, http.StatusBadRequest, "pcap_id不能为空")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "PCAP 数据源不可用")
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, ok := s.services.Store.GetUserByUsername(req.Username)
	if !ok || !u.IsActive || (u.Password != "" && req.Password != u.Password) {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	token := randomToken()
	s.tokens[token] = u.UserID
	now := time.Now().UTC()
	_, _ = s.services.Store.UpdateUser(u.UserID, map[string]any{"last_login_at": now})
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "access_token": token, "token_type": "bearer", "data": u})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: u})
}

func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) {
	_, ok := s.currentUser(r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": ok})
}

func (s *Server) initAdmin(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	u := domain.User{
		UserID:   firstNonEmpty(asString(body["user_id"]), "admin"),
		Username: firstNonEmpty(asString(body["username"]), "admin"),
		Password: firstNonEmpty(asString(body["password"]), "admin"),
		Email:    firstNonEmpty(asString(body["email"]), "admin@example.local"),
		Role:     "admin",
		Nickname: firstNonEmpty(asString(body["nickname"]), "管理员"),
	}
	created, err := s.services.Store.CreateUser(u)
	if err != nil {
		writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "管理员已存在", Data: map[string]any{"username": u.Username}})
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: created})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	u := domain.User{
		UserID:   asString(body["user_id"]),
		Username: asString(body["username"]),
		Nickname: asString(body["nickname"]),
		Email:    asString(body["email"]),
		Phone:    asString(body["phone"]),
		Password: firstNonEmpty(asString(body["password"]), "ChangeMe123!"),
		Role:     firstNonEmpty(asString(body["role"]), "user"),
	}
	if u.Username == "" {
		writeError(w, http.StatusBadRequest, "username不能为空")
		return
	}
	created, err := s.services.Store.CreateUser(u)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: created})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	newPassword := asString(body["new_password"])
	if newPassword == "" {
		newPassword = asString(body["password"])
	}
	if newPassword == "" {
		writeError(w, http.StatusBadRequest, "password不能为空")
		return
	}
	updated, _ := s.services.Store.UpdateUser(u.UserID, map[string]any{"password": newPassword})
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: updated})
}

func (s *Server) createEvent(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	e, err := s.services.CreateEventFromRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "事件创建成功", Data: e})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListEvents()})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	e, ok := s.services.Store.GetEvent(r.PathValue("event_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "事件不存在")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: e})
}

func (s *Server) getMessages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListMessages(r.PathValue("event_id"))})
}

func (s *Server) getTasks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListTasks(r.PathValue("event_id"))})
}

func (s *Server) getActions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListActions(r.PathValue("event_id"))})
}

func (s *Server) getCommands(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListCommands(r.PathValue("event_id"))})
}

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("event_id")
	data := map[string]any{
		"event_id":     eventID,
		"messages":     len(s.services.Store.ListMessages(eventID)),
		"tasks":        len(s.services.Store.ListTasks(eventID)),
		"actions":      len(s.services.Store.ListActions(eventID)),
		"commands":     len(s.services.Store.ListCommands(eventID)),
		"executions":   len(s.services.Store.ListExecutions(eventID)),
		"summaries":    len(s.services.Store.ListSummaries(eventID)),
		"generated_at": time.Now().UTC(),
	}
	if ev, ok := s.services.Store.GetEvent(eventID); ok {
		var c map[string]any
		_ = json.Unmarshal([]byte(ev.Context), &c)
		for _, key := range []string{"occurrence_count", "quant_stats", "stats_version", "data_version", "statistics_quality"} {
			data[key] = c[key]
		}
		if version, ok := c["stats_version"].(float64); ok && version > 0 {
			if snap, err := s.services.EvidenceSnapshot(r.Context(), eventID, int64(version)); err == nil {
				data["quant_stats"] = snap.Context["quant_stats"]
			} else {
				data["quant_stats"] = nil
				data["statistics_error"] = err.Error()
			}
		}
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: data})
}

func (s *Server) getSummaries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListSummaries(r.PathValue("event_id"))})
}

func (s *Server) sendEventMessage(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("event_id")
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	msg := domain.Message{
		EventID:         eventID,
		UserID:          asString(body["user_id"]),
		UserNickname:    asString(body["user_nickname"]),
		MessageFrom:     service.NormalizeMessageFrom(firstNonEmpty(asString(body["message_from"]), asString(body["sender"]), "user")),
		MessageType:     firstNonEmpty(asString(body["message_type"]), "user_message"),
		MessageContent:  firstNonEmpty(asString(body["message"]), asString(body["message_content"])),
		RoundID:         1,
		MessageCategory: "agent",
	}
	msg.SenderType = service.SenderType(msg.MessageFrom)
	created, err := s.services.Store.AddMessage(msg)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: created})
}

func (s *Server) getExecutions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListExecutions(r.PathValue("event_id"))})
}

func (s *Server) completeExecution(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "execution completion accepted", Data: map[string]string{"execution_id": r.PathValue("execution_id")}})
}

func (s *Server) getHierarchy(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("event_id")
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{
		"event_id":   eventID,
		"messages":   s.services.Store.ListMessages(eventID),
		"tasks":      s.services.Store.ListTasks(eventID),
		"actions":    s.services.Store.ListActions(eventID),
		"commands":   s.services.Store.ListCommands(eventID),
		"executions": s.services.Store.ListExecutions(eventID),
		"summaries":  s.services.Store.ListSummaries(eventID),
	}})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListUsers()})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.services.Store.GetUser(r.PathValue("user_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: u})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	u, ok := s.services.Store.UpdateUser(r.PathValue("user_id"), body)
	if !ok {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: u})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.services.Store.DeleteUser(r.PathValue("user_id")) {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "用户已删除"})
}

func (s *Server) updateUserPassword(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	pass := firstNonEmpty(asString(body["password"]), asString(body["new_password"]))
	if pass == "" {
		writeError(w, http.StatusBadRequest, "password不能为空")
		return
	}
	u, ok := s.services.Store.UpdateUser(r.PathValue("user_id"), map[string]any{"password": pass})
	if !ok {
		writeError(w, http.StatusNotFound, "用户不存在")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: u})
}

func (s *Server) promptList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: service.DefaultPrompts})
}

func (s *Server) promptGet(w http.ResponseWriter, r *http.Request) {
	role := r.PathValue("role")
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]string{"role": role, "prompt": service.DefaultPrompt(role)}})
}

func (s *Server) promptBackgroundGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]string{"name": name, "content": service.DefaultPrompt("background_" + name)}})
}

func (s *Server) drivingModeGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{"enabled": true, "mode": "auto"}})
}

func (s *Server) engineerChatSend(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	eventID := asString(body["event_id"])
	message := asString(body["message"])
	if eventID == "" || strings.TrimSpace(message) == "" {
		writeError(w, http.StatusBadRequest, "event_id和message不能为空")
		return
	}
	event, ok := s.services.Store.GetEvent(eventID)
	if !ok {
		writeError(w, http.StatusNotFound, "事件不存在")
		return
	}
	evidenceContext, evidenceErr := s.services.EvidenceContext(r.Context(), event)
	if evidenceErr != nil {
		writeError(w, http.StatusConflict, evidenceErr.Error())
		return
	}
	event.Context = evidenceContext
	_, _ = s.services.Store.AddMessage(domain.Message{EventID: eventID, MessageFrom: domain.RoleUser, MessageType: "user_message", MessageContent: message, RoundID: 1, MessageCategory: "engineer_chat", SenderType: "user"})
	prompt := s.engineerEventPrompt(event, message)
	reply, err := s.services.LLM.Chat(r.Context(), service.EngineerChatSystemPrompt, prompt)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	m, _ := s.services.Store.AddMessage(domain.Message{EventID: eventID, MessageFrom: domain.RoleAssistant, MessageType: "assistant_response", MessageContent: service.EvidenceReplyContent(reply, event.Context), RoundID: 1, MessageCategory: "engineer_chat", SenderType: "ai"})
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{"reply": reply, "message": m}})
}

func (s *Server) engineerChatHistory(w http.ResponseWriter, r *http.Request) {
	eventID := r.URL.Query().Get("event_id")
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: s.services.Store.ListMessages(eventID)})
}

func (s *Server) engineerNewSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{"session_id": randomToken()}})
}

func (s *Server) engineerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{"event_id": r.URL.Query().Get("event_id"), "status": "idle"}})
}

func (s *Server) reportGlobal(w http.ResponseWriter, r *http.Request) {
	events := s.services.Store.ListEvents()
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: map[string]any{"event_count": len(events), "generated_at": time.Now().UTC()}})
}

func (s *Server) flowShadowProxy(w http.ResponseWriter, r *http.Request) {
	s.services.FlowShadow.Proxy(w, r)
}

func (s *Server) ok(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success"})
}

func (s *Server) notImplemented(message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, domain.APIResponse{Status: "accepted", Message: message})
	}
}

func (s *Server) requireInternalKey(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.InternalAPIKey == "" || r.Header.Get("X-API-Key") == s.cfg.InternalAPIKey {
		return true
	}
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
	return false
}

func (s *Server) currentUser(r *http.Request) (domain.User, bool) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return domain.User{}, false
	}
	userID, ok := s.tokens[token]
	if !ok {
		return domain.User{}, false
	}
	return s.services.Store.GetUser(userID)
}

func (s *Server) audit(r *http.Request, action, target, meta string) {
	actor := firstNonEmpty(r.Header.Get("X-Actor"), "deepsoc")
	s.services.Store.AddAuditLog(domain.AuditLog{Actor: actor, Action: action, Target: target, Meta: meta})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, domain.APIResponse{Status: "error", Message: message})
}

func statusText(ok bool) string {
	if ok {
		return "success"
	}
	return "error"
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-API-Key,X-Actor")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return strings.Trim(string(b), `"`)
	}
}

func intValue(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *Server) internalDedupReset(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"result": "ok",
		"data": map[string]any{
			"reset":   true,
			"message": "dedup reset completed",
		},
	})
}
