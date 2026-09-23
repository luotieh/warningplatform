package traffic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/client"
	trafficconfig "vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/lyserver"
	"vulnscan-backend/traffic/internal/socketio"
	"vulnscan-backend/traffic/internal/store"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	events  *EventService
	assets  *AssetService
	reports *AssetReportService
	account *AccountService
	chat    *ChatService
	system  *SystemService
	inner   *InternalService
	ly      *lyserver.Service
	socket  *socketio.Hub
}

func NewHandler(events *EventService, assets *AssetService, reports *AssetReportService, account *AccountService, chat *ChatService, system *SystemService, inner *InternalService, ly *lyserver.Service, socket *socketio.Hub) *Handler {
	return &Handler{events: events, assets: assets, reports: reports, account: account, chat: chat, system: system, inner: inner, ly: ly, socket: socket}
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
		if _, ok := body["max_tokens"]; ok {
			settings.MaxTokens = intFromBody(body["max_tokens"])
		}
		if _, ok := body["disable_thinking"]; ok {
			settings.DisableThinking = boolFromBody(body["disable_thinking"])
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

// TestLLMConfig 用表单传入的 LLM 参数做一次真实健康探测（POST /llm/config/test，不落盘）。
func (h *Handler) TestLLMConfig(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	settings := trafficconfig.LLMSettings{
		BaseURL: strings.TrimSpace(stringValue(body["base_url"])),
		Model:   strings.TrimSpace(stringValue(body["model"])),
		APIKey:  strings.TrimSpace(stringValue(body["api_key"])),
	}
	if timeout := intFromBody(body["timeout_seconds"]); timeout > 0 {
		settings.TimeoutSeconds = timeout
	}
	result := h.system.TestLLMConfig(settings)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{
		"code":    successCode,
		"data":    result,
		"message": map[bool]string{true: "连接正常", false: "连接失败"}[result.OK],
	})
}

// StoreConfig 读取/保存 MySQL 存储配置（GET/POST/PUT /store/config）。
func (h *Handler) StoreConfig(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		ok(c, h.system.StoreConfig())
	case http.MethodPost, http.MethodPut:
		body, valid := readBody(c)
		if !valid {
			return
		}
		settings := h.system.StoreConfig()
		if v := strings.TrimSpace(stringValue(body["store_backend"])); v != "" {
			settings.StoreBackend = v
		}
		if v := strings.TrimSpace(stringValue(body["host"])); v != "" {
			settings.Host = v
		}
		if port := intFromBody(body["port"]); port > 0 {
			settings.Port = port
		}
		if v := strings.TrimSpace(stringValue(body["user"])); v != "" {
			settings.User = v
		}
		if v := strings.TrimSpace(stringValue(body["db_name"])); v != "" {
			settings.DBName = v
		}
		if _, ok := body["auto_migrate"]; ok {
			settings.AutoMigrate = boolFromBody(body["auto_migrate"])
		}
		if wait := intFromBody(body["db_wait_seconds"]); wait > 0 {
			settings.DBWaitSeconds = wait
		}
		password := strings.TrimSpace(stringValue(body["password"]))
		updatePassword := password != ""
		if updatePassword {
			settings.Password = password
		}
		updated, err := h.system.SetStoreConfig(settings, updatePassword)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		okMessage(c, "MySQL配置已保存，存储后端变更需重启后生效", updated)
	default:
		fail(c, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// TestStoreConfig 测试 MySQL 连通性与核心表（POST /store/config/test，不落盘）。
func (h *Handler) TestStoreConfig(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	settings := storeSettingsFromBody(body, h.system.StoreConfig())
	result := h.system.TestStoreConfig(settings)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"code": 0, "data": result, "message": map[bool]string{true: "连接正常", false: "连接失败"}[result.OK]})
}

// storeSettingsFromBody 从请求体解析 MySQL 测试参数；
// 请求未携带 password 时回填当前配置中的密码（与“留空不修改”语义一致），
// 避免测试连接因空密码误报 Access denied。
func storeSettingsFromBody(body map[string]any, current trafficconfig.StoreSettings) trafficconfig.StoreSettings {
	settings := trafficconfig.StoreSettings{StoreBackend: "mysql"}
	if v := strings.TrimSpace(stringValue(body["host"])); v != "" {
		settings.Host = v
	}
	if port := intFromBody(body["port"]); port > 0 {
		settings.Port = port
	}
	if v := strings.TrimSpace(stringValue(body["user"])); v != "" {
		settings.User = v
	}
	if v := strings.TrimSpace(stringValue(body["password"])); v != "" {
		settings.Password = v
	}
	if _, hasPassword := body["password"]; !hasPassword {
		settings.Password = current.Password
	}
	if v := strings.TrimSpace(stringValue(body["db_name"])); v != "" {
		settings.DBName = v
	}
	return settings
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
	// 服务端分页/过滤：scope=today（未归档）/ archive（日期范围可选）/ all（全局搜索）。
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	q := store.EventQuery{
		Scope:       c.DefaultQuery("scope", "today"),
		Date:        c.Query("date"),
		ArchiveFrom: c.Query("archive_from"),
		ArchiveTo:   c.Query("archive_to"),
		Page:        page,
		PageSize:    pageSize,
		Level:       c.Query("level"),
		Keyword:     c.Query("keyword"),
		Asset:       c.Query("asset"),
		// 排序：sort=time|payload|frequency|probability，order=desc|asc（非法值由 store 兜底默认）。
		Sort:  c.Query("sort"),
		Order: c.Query("order"),
	}
	if v := c.Query("starttime"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.Unix(sec, 0).UTC()
			q.StartTime = &t
		}
	}
	if v := c.Query("endtime"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.Unix(sec, 0).UTC()
			q.EndTime = &t
		}
	}
	if _, _, err := q.ArchiveRange(); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	items, total, err := h.events.ListPage(c.Request.Context(), q)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	ok(c, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize})
}

// GetArchiveJob 查询每日归档任务（GET /events/archive/jobs/:jobID）。
func (h *Handler) GetArchiveJob(c *gin.Context) {
	job, found := h.events.GetArchiveJob(c.Param("jobID"))
	if !found {
		fail(c, http.StatusNotFound, "归档任务不存在")
		return
	}
	ok(c, job)
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

func (h *Handler) EventOccurrences(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	version, _ := strconv.ParseInt(c.Query("snapshot_version"), 10, 64)
	page, err := h.events.Occurrences(c.Request.Context(), c.Param("eventID"), c.Query("cursor"), c.Param("hitID"), limit, version, c.Query("from"), c.Query("to"))
	if err != nil {
		fail(c, 400, err.Error())
		return
	}
	ok(c, page)
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

// RefreshEventReport 手动刷新事件分析报告（POST /events/detail/:eventID/report/refresh）。
func (h *Handler) RefreshEventReport(c *gin.Context) {
	result, err := h.events.RefreshReport(c.Request.Context(), c.Param("eventID"))
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if result["status"] == "already_running" {
		okMessage(c, "该事件正在分析中，请稍后查看", result)
		return
	}
	okMessage(c, "分析刷新任务已提交，完成后自动更新", result)
}

// EventEvidence 管理端代理下载事件 PCAP 证据（GET /events/detail/:eventID/evidence/:idx）。
func (h *Handler) EventEvidence(c *gin.Context) {
	idx, err := strconv.Atoi(c.Param("idx"))
	if err != nil || idx < 0 {
		fail(c, http.StatusBadRequest, "证据序号非法")
		return
	}
	var data []byte
	var name, contentType string
	if c.Param("hitID") != "" {
		data, name, contentType, err = h.inner.HitEvidenceFile(c.Request.Context(), c.Param("eventID"), c.Param("hitID"), idx)
	} else {
		data, name, contentType, err = h.inner.EvidenceFile(c.Request.Context(), c.Param("eventID"), idx)
	}
	if err != nil {
		switch {
		case errors.Is(err, errEventNotFound), errors.Is(err, errEvidenceNotFound):
			fail(c, http.StatusNotFound, err.Error())
		case errors.Is(err, errEvidenceInvalid):
			fail(c, http.StatusBadRequest, err.Error())
		default:
			fail(c, http.StatusBadGateway, err.Error())
		}
		return
	}
	safeName := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, name)
	if safeName == "" {
		safeName = "evidence.pcap"
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeName))
	c.Data(http.StatusOK, contentType, data)
}

// EventEvidenceArchive 聚合事件全部 PCAP 打包下载（GET /events/detail/:eventID/evidence/archive）。
func (h *Handler) EventEvidenceArchive(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), evidenceArchiveTimeout)
	defer cancel()
	dir, res, err := h.inner.EvidenceArchive(ctx, c.Param("eventID"))
	if err != nil {
		switch {
		case errors.Is(err, errEventNotFound), errors.Is(err, errEvidenceNotFound):
			fail(c, http.StatusNotFound, err.Error())
		case errors.Is(err, errEvidenceInvalid):
			fail(c, http.StatusBadRequest, err.Error())
		case errors.Is(err, errEvidenceTooLarge):
			fail(c, http.StatusRequestEntityTooLarge, err.Error())
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			fail(c, http.StatusGatewayTimeout, err.Error())
		default:
			fail(c, http.StatusBadGateway, err.Error())
		}
		return
	}
	if dir == "" {
		fail(c, http.StatusBadGateway, "证据打包失败")
		return
	}
	defer os.RemoveAll(dir)
	zipPath := filepath.Join(dir, "archive.zip")
	safeName := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, c.Param("eventID"))
	if safeName == "" {
		safeName = "event"
	}
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_evidence.zip"`, safeName))
	if res.Failed > 0 {
		c.Header("X-Evidence-Failed", strconv.Itoa(res.Failed))
	}
	c.File(zipPath)
}

// RunAssetMonthlySummary 创建资产 IP 月度总结异步任务（POST /assets/monthly-summary/run）。
func (h *Handler) RunAssetMonthlySummary(c *gin.Context) {
	period := ""
	if body, valid := readBody(c); valid {
		period = firstString(body, "period")
	}
	job, err := h.reports.RunMonthlyAsync(c.Request.Context(), period)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	okMessage(c, "月度总结任务已创建，可通过 job_id 查询进度", job)
}

// GetAssetMonthlyJob 查询月度总结任务进度（GET /assets/monthly-summary/jobs/:jobID）。
func (h *Handler) GetAssetMonthlyJob(c *gin.Context) {
	job, err := h.reports.GetJob(c.Param("jobID"))
	if err != nil {
		fail(c, http.StatusNotFound, err.Error())
		return
	}
	ok(c, job)
}

// GetAssetMonthlySummary 查询资产月度总结（GET /assets/:id/monthly-summary?period=）。
func (h *Handler) GetAssetMonthlySummary(c *gin.Context) {
	period := strings.TrimSpace(c.Query("period"))
	if period != "" {
		sm, found := h.reports.GetMonthly(c.Param("id"), period)
		if !found {
			fail(c, http.StatusNotFound, "该资产指定月份暂无月度总结")
			return
		}
		ok(c, sm)
		return
	}
	ok(c, h.reports.ListMonthly(c.Param("id")))
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
		switch {
		case errors.As(err, &llmErr):
			fail(c, http.StatusBadGateway, err.Error())
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

func (h *Handler) EngineerChatEstimate(c *gin.Context) {
	body, valid := readBody(c)
	if !valid {
		return
	}
	result, err := h.chat.Estimate(stringValue(body["event_id"]), stringValue(body["message"]))
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}
	ok(c, result)
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
	// Gin 通配参数在不同路由挂载方式下可能带或不带前导斜杠。
	// 统一后再匹配，避免合法的 /internal/event/push 被误报为路由不存在。
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
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
