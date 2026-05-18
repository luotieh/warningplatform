package notify

import (
	"fmt"
	"log/slog"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type ServiceNotify struct {
	db *db.DB
}

func NewServiceNotify(database *db.DB) *ServiceNotify {
	return &ServiceNotify{db: database}
}

func (s *ServiceNotify) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// List returns notifications filtered by user, read status, and type.
func (s *ServiceNotify) List(userID, readFilter, notifyType string) ([]model.Notification, int64) {
	var items []model.Notification
	var count int64

	tx := s.session().Model(&model.Notification{})

	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}

	if readFilter == "false" {
		tx = tx.Where("`read` = ?", false)
	}

	if notifyType != "" {
		tx = tx.Where("type = ?", notifyType)
	}

	tx.Count(&count)
	tx.Order("created_at DESC").Limit(50).Find(&items)
	return items, count
}

// UnreadCount returns the number of unread notifications for a user.
func (s *ServiceNotify) UnreadCount(userID string) int64 {
	var count int64
	tx := s.session().Model(&model.Notification{}).Where("`read` = ?", false)
	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}
	tx.Count(&count)
	return count
}

// MarkRead marks a single notification as read.
func (s *ServiceNotify) MarkRead(id string) {
	now := time.Now()
	s.session().Model(&model.Notification{}).Where("id = ?", id).Updates(map[string]any{
		"read":    true,
		"read_at": &now,
	})
}

// MarkAllRead marks all unread notifications as read for a user.
func (s *ServiceNotify) MarkAllRead(userID string) {
	now := time.Now()
	tx := s.session().Model(&model.Notification{}).Where("`read` = ?", false)
	if userID != "" {
		tx = tx.Where("user_id = ? OR user_id = ''", userID)
	}
	tx.Updates(map[string]any{"read": true, "read_at": &now})
}

// Delete removes a notification by ID.
func (s *ServiceNotify) Delete(id string) {
	s.session().Where("id = ?", id).Delete(&model.Notification{})
}

// --- Sender methods (for programmatic notification creation) ---

// NotifyTaskComplete creates a notification for a completed scan task.
func (s *ServiceNotify) NotifyTaskComplete(task *model.ScanTask) {
	s.create("", model.NotifyTypeTaskComplete,
		fmt.Sprintf("扫描任务完成: %s", task.Name),
		fmt.Sprintf("任务 %s 已完成，共发现目标 %d 个", task.Name, task.TotalTargets),
		fmt.Sprintf("/scan/task/%s", task.ID),
		"info", task.ID, "",
	)
}

// NotifyTaskFailed creates a notification for a failed scan task.
func (s *ServiceNotify) NotifyTaskFailed(task *model.ScanTask, reason string) {
	s.create("", model.NotifyTypeTaskFailed,
		fmt.Sprintf("扫描任务失败: %s", task.Name),
		fmt.Sprintf("任务 %s 执行失败: %s", task.Name, reason),
		fmt.Sprintf("/scan/task/%s", task.ID),
		"error", task.ID, "",
	)
}

// NotifyHighVuln creates a notification for a high/critical vulnerability.
func (s *ServiceNotify) NotifyHighVuln(vuln *model.Vulnerability) {
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

func (s *ServiceNotify) create(userID, notifyType, title, content, link, severity, taskID, vulnID string) {
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
	if err := s.session().Create(&n).Error; err != nil {
		slog.Error("创建通知失败", "error", err)
	}
}
