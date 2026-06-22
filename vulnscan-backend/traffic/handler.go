package traffic

import (
	"net/http"
	"strings"

	"vulnscan-backend/traffic/internal/lyserver"
	"vulnscan-backend/traffic/internal/socketio"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	events  *EventService
	account *AccountService
	chat    *ChatService
	system  *SystemService
	inner   *InternalService
	ly      *lyserver.Service
	socket  *socketio.Hub
}

func NewHandler(events *EventService, account *AccountService, chat *ChatService, system *SystemService, inner *InternalService, ly *lyserver.Service, socket *socketio.Hub) *Handler {
	return &Handler{events: events, account: account, chat: chat, system: system, inner: inner, ly: ly, socket: socket}
}

func (h *Handler) Health(c *gin.Context) {
	ok(c, h.system.Health())
}

func (h *Handler) LLMHealth(c *gin.Context) {
	ok(c, h.system.LLMHealth(c.Request.Context()))
}

func (h *Handler) LLMConfig(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		ok(c, h.system.LLMConfig())
	case http.MethodPost, http.MethodPut:
		body, valid := readBody(c)
		if !valid {
			return
		}
		settings := h.system.LLMConfig()
		if _, ok := body["base_url"]; ok {
			settings.BaseURL = strings.TrimSpace(stringValue(body["base_url"]))
		}
		if v := strings.TrimSpace(stringValue(body["model"])); v != "" {
			settings.Model = v
		}
		if timeout := intFromBody(body["timeout_seconds"]); timeout > 0 {
			settings.TimeoutSeconds = timeout
		}
		apiKey := strings.TrimSpace(stringValue(body["api_key"]))
		updateAPIKey := apiKey != ""
		if updateAPIKey {
			settings.APIKey = apiKey
		}
		updated, err := h.system.SetLLMConfig(settings, updateAPIKey)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		h.chat.UpdateLLM(updated)
		okMessage(c, "LLM配置已保存", h.system.LLMConfig())
	default:
		fail(c, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) Version(c *gin.Context) {
	ok(c, h.system.Version())
}

func (h *Handler) ReportGlobal(c *gin.Context) {
	ok(c, h.system.ReportGlobal())
}

func (h *Handler) DeepSOCAuthLogin(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	token, user, err := h.account.Login(stringValue(body["username"]), stringValue(body["password"]))
	if err != nil {
		fail(c, http.StatusUnauthorized, err.Error())
		return
	}
	authOK(c, token, user)
}

func (h *Handler) DeepSOCAuthLogout(c *gin.Context) {
	h.account.Logout(tokenFromAuthHeader(c.GetHeader("Authorization")))
	ok(c, nil)
}

func (h *Handler) DeepSOCAuthMe(c *gin.Context) {
	user, found := h.account.CurrentUser(c.GetHeader("Authorization"))
	if !found {
		fail(c, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	ok(c, user)
}

func (h *Handler) DeepSOCCheckAuth(c *gin.Context) {
	_, found := h.account.CurrentUser(c.GetHeader("Authorization"))
	ok(c, gin.H{"authenticated": found})
}

func (h *Handler) DeepSOCInitAdmin(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	user, created, _ := h.account.InitAdmin(body)
	if !created {
		okMessage(c, "管理员已存在", gin.H{"username": user.Username})
		return
	}
	ok(c, user)
}

func (h *Handler) CreateEvent(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	event, err := h.events.Create(c.Request.Context(), body)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	okMessage(c, "事件创建成功", event)
}

func (h *Handler) ListEvents(c *gin.Context) {
	ok(c, h.events.List(c.Request.Context()))
}

func (h *Handler) GetEvent(c *gin.Context) {
	event, found := h.events.Detail(c.Request.Context(), c.Param("eventID"))
	if !found {
		fail(c, 404, "事件不存在")
		return
	}
	ok(c, event)
}

func (h *Handler) EventMessages(c *gin.Context) {
	ok(c, h.events.Messages(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) EventTasks(c *gin.Context) {
	ok(c, h.events.Tasks(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) EventActions(c *gin.Context) {
	ok(c, h.events.Actions(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) EventCommands(c *gin.Context) {
	ok(c, h.events.Commands(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) EventStats(c *gin.Context) {
	ok(c, h.events.Stats(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) EventSummaries(c *gin.Context) {
	ok(c, h.events.Summaries(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) SendEventMessage(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	msg, err := h.events.SendMessage(c.Request.Context(), c.Param("eventID"), body)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	ok(c, msg)
}

func (h *Handler) EventExecutions(c *gin.Context) {
	ok(c, h.events.Executions(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) CompleteExecution(c *gin.Context) {
	okMessage(c, "execution completion accepted", h.events.CompleteExecution(c.Request.Context(), c.Param("executionID")))
}

func (h *Handler) EventHierarchy(c *gin.Context) {
	ok(c, h.events.Hierarchy(c.Request.Context(), c.Param("eventID")))
}

func (h *Handler) Users(c *gin.Context) {
	ok(c, h.account.ListUsers())
}

func (h *Handler) UserCreate(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	user, err := h.account.CreateUser(body)
	if err != nil {
		fail(c, http.StatusConflict, err.Error())
		return
	}
	ok(c, user)
}

func (h *Handler) UserDetail(c *gin.Context) {
	userID := c.Param("userID")
	switch c.Request.Method {
	case http.MethodGet:
		user, found := h.account.Detail(userID)
		if !found {
			fail(c, http.StatusNotFound, "用户不存在")
			return
		}
		ok(c, user)
	case http.MethodPut:
		body, valid := readBody(c)
		if !valid {
			return
		}
		user, found := h.account.Update(userID, body)
		if !found {
			fail(c, http.StatusNotFound, "用户不存在")
			return
		}
		ok(c, user)
	case http.MethodDelete:
		if !h.account.Delete(userID) {
			fail(c, http.StatusNotFound, "用户不存在")
			return
		}
		okMessage(c, "用户已删除", nil)
	default:
		fail(c, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) UserPassword(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	user, found, err := h.account.UpdatePassword(c.Param("userID"), body)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	ok(c, user)
}

func (h *Handler) PromptList(c *gin.Context) {
	ok(c, h.system.PromptList())
}

func (h *Handler) PromptRole(c *gin.Context) {
	ok(c, h.system.Prompt(c.Param("role")))
}

func (h *Handler) PromptBackground(c *gin.Context) {
	ok(c, h.system.PromptBackground(c.Param("name")))
}

func (h *Handler) DrivingMode(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		ok(c, gin.H{"enabled": true, "mode": "auto"})
	case http.MethodPut:
		body, valid := readBody(c)
		if !valid {
			return
		}
		if err := h.system.SetDrivingMode(c.Request.Context(), true); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		_ = body
		ok(c, gin.H{"enabled": true, "mode": "auto"})
	default:
		fail(c, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) EngineerChatSend(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	result, err := h.chat.Send(c.Request.Context(), body)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "不能为空"):
			fail(c, http.StatusBadRequest, err.Error())
		case strings.Contains(err.Error(), "不存在"):
			fail(c, http.StatusNotFound, err.Error())
		default:
			fail(c, http.StatusBadGateway, err.Error())
		}
		return
	}
	ok(c, result)
}

func (h *Handler) EngineerChatHistory(c *gin.Context) {
	ok(c, h.chat.History(c.Request.Context(), c.Query("event_id")))
}

func (h *Handler) EngineerChatNewSession(c *gin.Context) {
	ok(c, h.chat.NewSession(c.Request.Context()))
}

func (h *Handler) EngineerChatStatus(c *gin.Context) {
	ok(c, h.chat.Status(c.Request.Context(), c.Query("event_id")))
}

func (h *Handler) Ly(c *gin.Context) {
	switch c.Param("path") {
	case "/auth":
		h.ly.Auth(c.Writer, c.Request)
	case "/sctl":
		h.ly.Status(c.Writer, c.Request)
	case "/config":
		if c.Request.Method == http.MethodPost {
			h.ly.SetConfig(c.Writer, c.Request)
			return
		}
		h.ly.GetConfig(c.Writer, c.Request)
	case "/mo":
		if c.Request.Method == http.MethodPost {
			h.ly.SetMO(c.Writer, c.Request)
			return
		}
		h.ly.GetMO(c.Writer, c.Request)
	case "/bwlist":
		if c.Request.Method == http.MethodPost {
			h.ly.SetBWList(c.Writer, c.Request)
			return
		}
		h.ly.GetBWList(c.Writer, c.Request)
	case "/event":
		if !h.ly.Enabled() {
			ok(c, h.events.LyCompatibleList(c.Request.Context()))
			return
		}
		h.ly.Event(c.Writer, c.Request)
	case "/feature":
		h.ly.Feature(c.Writer, c.Request)
	case "/topn":
		h.ly.TopN(c.Writer, c.Request)
	case "/evidence":
		h.ly.Evidence(c.Writer, c.Request)
	case "/rules":
		h.ly.Rules(c.Writer, c.Request)
	case "/rules/config":
		h.ly.RulesConfig(c.Writer, c.Request)
	default:
		fail(c, http.StatusNotFound, "ly compatibility route not found")
	}
}

func (h *Handler) Internal(c *gin.Context) {
	path := c.Param("path")
	switch {
	case c.Request.Method == http.MethodPost && path == "/event/push":
		body, valid := readBody(c)
		if !valid {
			return
		}
		res, err := h.inner.PushEvent(c.Request.Context(), body, internalAPIKey(c))
		if err != nil {
			fail(c, http.StatusUnauthorized, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodPost && path == "/sync:run":
		res, err := h.inner.SyncRun(c.Request.Context())
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodPost && path == "/admin/dedup/reset":
		ok(c, h.inner.DedupReset())
	case c.Request.Method == http.MethodGet && strings.HasPrefix(path, "/flows/") && strings.HasSuffix(path, "/related"):
		flowID := strings.TrimSuffix(strings.TrimPrefix(path, "/flows/"), "/related")
		res, err := h.inner.RelatedFlows(c.Request.Context(), flowID)
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodGet && strings.HasPrefix(path, "/flows/"):
		flowID := strings.TrimPrefix(path, "/flows/")
		res, err := h.inner.Flow(c.Request.Context(), flowID)
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodGet && strings.HasPrefix(path, "/assets/"):
		ip := strings.TrimPrefix(path, "/assets/")
		res, err := h.inner.Asset(c.Request.Context(), ip)
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodPost && strings.HasPrefix(path, "/flows/") && strings.HasSuffix(path, "/pcap:prepare"):
		flowID := strings.TrimSuffix(strings.TrimPrefix(path, "/flows/"), "/pcap:prepare")
		res, err := h.inner.PreparePCAP(c.Request.Context(), flowID)
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	case c.Request.Method == http.MethodGet && strings.HasPrefix(path, "/pcaps/"):
		pcapID := strings.TrimPrefix(path, "/pcaps/")
		res, err := h.inner.PCAP(c.Request.Context(), pcapID)
		if err != nil {
			fail(c, http.StatusBadGateway, err.Error())
			return
		}
		ok(c, res)
	default:
		fail(c, http.StatusNotFound, "internal route not found")
	}
}

func internalAPIKey(c *gin.Context) string {
	if key := strings.TrimSpace(c.GetHeader("X-API-Key")); key != "" {
		return key
	}
	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[len("Bearer "):])
	}
	return ""
}

func (h *Handler) SocketIO(c *gin.Context) {
	h.socket.ServeHTTP(c.Writer, c.Request)
}
