package traffic

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/lyserver"
	"vulnscan-backend/traffic/internal/socketio"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	events  *EventService
	assets  *AssetService
	account *AccountService
	chat    *ChatService
	system  *SystemService
	inner   *InternalService
	ly      *lyserver.Service
	socket  *socketio.Hub
}

func NewHandler(events *EventService, assets *AssetService, account *AccountService, chat *ChatService, system *SystemService, inner *InternalService, ly *lyserver.Service, socket *socketio.Hub) *Handler {
	return &Handler{events: events, assets: assets, account: account, chat: chat, system: system, inner: inner, ly: ly, socket: socket}
}

func (h *Handler) Health(c *gin.Context) {
	ok(c, h.system.Health())
}

func (h *Handler) LLMHealth(c *gin.Context) {
	ok(c, h.system.LLMHealth(c.Request.Context()))
}

// LLMHealthTest 供模型配置页"健康检查"按钮使用：以请求体中的表单值
// （base_url/model/api_key/timeout_seconds，均可缺省回退已保存配置）
// 测试连通性并发送一条测试对话。
func (h *Handler) LLMHealthTest(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	ok(c, h.system.LLMHealthTest(
		c.Request.Context(),
		stringValue(body["base_url"]),
		stringValue(body["model"]),
		stringValue(body["api_key"]),
		intFromBody(body["timeout_seconds"]),
	))
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

func (h *Handler) ReviewEvent(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	action := strings.ToLower(strings.TrimSpace(firstString(body, "action")))
	comment := firstString(body, "comment", "review_comment")
	reviewedBy := firstString(body, "reviewed_by")
	bearer := c.GetHeader("Authorization")
	result, err := h.events.Review(c.Request.Context(), c.Param("eventID"), action, comment, reviewedBy, bearer, requestBaseURL(c))
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	ok(c, result)
}

// requestBaseURL 由入站请求推导同机 base（CircularClient.BaseURL 为空时使用）。
func requestBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + c.Request.Host
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
		var llmErr *client.LLMCallError
		if errors.As(err, &llmErr) {
			c.JSON(http.StatusBadGateway, gin.H{
				"code": http.StatusBadGateway, "message": llmErr.Message,
				"error_code": llmErr.Code, "stage": llmErr.Stage, "hint": llmErr.Hint,
				"upstream_status": llmErr.UpstreamStatus, "detail": llmErr.Detail,
				"request_id": c.Writer.Header().Get("X-Request-Id"),
			})
			return
		}
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
	// Gin wildcard parameters may be returned with or without the leading
	// slash depending on the router/version. Normalize before dispatching so
	// /api/traffic/internal/event/push consistently matches this handler.
	path := "/" + strings.TrimPrefix(c.Param("path"), "/")
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

func (h *Handler) ListAssets(c *gin.Context) {
	keyword := strings.ToLower(strings.TrimSpace(c.Query("keyword")))
	typ := strings.TrimSpace(c.Query("type"))
	statusQ := strings.TrimSpace(c.Query("status"))
	out := []any{}
	for _, a := range h.assets.List() {
		if typ != "" && a.AssetType != typ {
			continue
		}
		if statusQ != "" && stringValue(a.Status) != statusQ {
			continue
		}
		if keyword != "" &&
			!strings.Contains(strings.ToLower(a.Name), keyword) &&
			!strings.Contains(strings.ToLower(a.Address), keyword) {
			continue
		}
		out = append(out, a)
	}
	ok(c, out)
}

func (h *Handler) CreateAsset(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	// 未显式提供 status 时默认启用(1)；显式传入(含 0=停用)则尊重之。
	status := 1
	if _, ok := body["status"]; ok {
		status = intFromBody(body["status"])
	}
	created, err := h.assets.Create(domain.Asset{
		Name:      firstString(body, "name"),
		AssetType: firstString(body, "asset_type", "type"),
		Address:   firstString(body, "address"),
		Unit:      firstString(body, "unit"),
		Owner:     firstString(body, "owner"),
		Remark:    firstString(body, "remark"),
		Status:    status,
	})
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	okMessage(c, "资产已创建", created)
}

func (h *Handler) UpdateAsset(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	patch := map[string]any{}
	for _, k := range []string{"name", "address", "unit", "owner", "remark"} {
		if v, ok := body[k]; ok {
			patch[k] = stringValue(v)
		}
	}
	if v, ok := body["asset_type"]; ok {
		patch["asset_type"] = stringValue(v)
	} else if v, ok := body["type"]; ok {
		patch["asset_type"] = stringValue(v)
	}
	if v, ok := body["status"]; ok {
		patch["status"] = intFromBody(v)
	}
	updated, found, err := h.assets.Update(c.Param("id"), patch)
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	if !found {
		fail(c, 404, "资产不存在")
		return
	}
	okMessage(c, "资产已更新", updated)
}

func (h *Handler) DeleteAsset(c *gin.Context) {
	if !h.assets.Delete(c.Param("id")) {
		fail(c, 404, "资产不存在")
		return
	}
	okMessage(c, "资产已删除", nil)
}

func (h *Handler) ImportAssets(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		fail(c, 400, "文件上传失败")
		return
	}
	f, err := fh.Open()
	if err != nil {
		fail(c, 400, "文件打开失败")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		fail(c, 400, "文件读取失败")
		return
	}
	imported, errs := h.assets.Import(fh.Filename, data)
	ok(c, map[string]any{"imported": imported, "errors": errs})
}

func (h *Handler) AssetImportTemplate(c *gin.Context) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=asset_import_template.csv")
	// 加 UTF-8 BOM，Excel 打开中文不乱码
	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})
	c.Writer.Write(AssetImportTemplateCSV())
}
