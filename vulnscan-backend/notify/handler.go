package notify

import (
	"fmt"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"code.yt-security.com/public/sdk/middleware"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Sender struct {
	db *gorm.DB
}

func NewSender(db *gorm.DB) *Sender {
	return &Sender{db: db}
}

func (s *Sender) NotifyTaskComplete(task *model.ScanTask) {
	s.create("", model.NotifyTypeTaskComplete,
		fmt.Sprintf("扫描任务完成: %s", task.Name),
		fmt.Sprintf("任务 %s 已完成，共发现目标 %d 个", task.Name, task.TotalTargets),
		fmt.Sprintf("/scan/task/%s", task.ID),
		"info", task.ID, "",
	)
}

func (s *Sender) NotifyTaskFailed(task *model.ScanTask, reason string) {
	s.create("", model.NotifyTypeTaskFailed,
		fmt.Sprintf("扫描任务失败: %s", task.Name),
		fmt.Sprintf("任务 %s 执行失败: %s", task.Name, reason),
		fmt.Sprintf("/scan/task/%s", task.ID),
		"error", task.ID, "",
	)
}

func (s *Sender) NotifyHighVuln(vuln *model.Vulnerability) {
	notifyType := model.NotifyTypeVulnHigh
	if vuln.Severity == model.SeverityCritical {
		notifyType = model.NotifyTypeVulnCritical
	}

	s.create("", notifyType,
		fmt.Sprintf("[%s] %s", vuln.Severity, vuln.Title),
		fmt.Sprintf("目标 %s 发现%s漏洞: %s", vuln.Target, vuln.Severity, vuln.Title),
		fmt.Sprintf("/vuln/%s", vuln.ID),
		vuln.Severity, vuln.TaskID, vuln.ID,
	)
}

func (s *Sender) create(userID, notifyType, title, content, link, severity, taskID, vulnID string) {
	n := model.Notification{
		ID:       qulid.GenerateID(),
		UserID:   userID,
		Type:     notifyType,
		Title:    title,
		Content:  content,
		Link:     link,
		Severity: severity,
		TaskID:   taskID,
		VulnID:   vulnID,
	}
	if err := s.db.Create(&n).Error; err != nil {
		slog.Error("创建通知失败", "error", err)
	}
}

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) List(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	var items []model.Notification
	tx := h.db.Model(&model.Notification{})

	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}

	readFilter := c.DefaultQuery("read", "")
	if readFilter == "false" {
		tx = tx.Where("`read` = ?", false)
	}

	notifyType := c.Query("type")
	if notifyType != "" {
		tx = tx.Where("type = ?", notifyType)
	}

	var count int64
	tx.Count(&count)

	tx.Order("created_at DESC").Limit(50).Find(&items)
	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *Handler) UnreadCount(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	var count int64
	tx := h.db.Model(&model.Notification{}).Where("`read` = ?", false)
	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}
	tx.Count(&count)

	web.RespContent(c, web.Success, gin.H{"count": count})
}

func (h *Handler) MarkRead(c *gin.Context) {
	id := c.Param("id")
	now := time.Now()
	h.db.Model(&model.Notification{}).Where("id = ?", id).Updates(map[string]any{
		"read":    true,
		"read_at": &now,
	})
	web.Resp(c, web.Success)
}

func (h *Handler) MarkAllRead(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	now := time.Now()
	tx := h.db.Model(&model.Notification{}).Where("`read` = ?", false)
	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}
	tx.Updates(map[string]any{"read": true, "read_at": &now})
	web.Resp(c, web.Success)
}

type NotifyRoutes struct {
	handler *Handler
}

func NewNotifyRoutes(handler *Handler) *NotifyRoutes {
	return &NotifyRoutes{handler: handler}
}

func (m *NotifyRoutes) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/notify"), []authorize.Route{
		{
			Name: "站内通知", Enabled: true,
			Children: []authorize.Route{
				{Name: "通知列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
				{Name: "未读数量", Path: "unread-count", Method: "GET", Handler: m.handler.UnreadCount, Enabled: true},
				{Name: "标记已读", Path: ":id/read", Method: "POST", Handler: m.handler.MarkRead, Enabled: true},
				{Name: "全部已读", Path: "read-all", Method: "POST", Handler: m.handler.MarkAllRead, Enabled: true},
			},
		},
	})
}
