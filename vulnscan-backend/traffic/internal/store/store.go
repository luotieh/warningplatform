package store

import (
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

type Store interface {
	CreateUser(u domain.User) (domain.User, error)
	GetUserByUsername(username string) (domain.User, bool)
	GetUser(userID string) (domain.User, bool)
	ListUsers() []domain.User
	UpdateUser(userID string, patch map[string]any) (domain.User, bool)
	DeleteUser(userID string) bool

	CreateEvent(e domain.Event) (domain.Event, error)
	GetEvent(eventID string) (domain.Event, bool)
	ListEvents() []domain.Event
	ListEventsPage(q EventQuery) (EventPage, error)
	ListEventsConvergedDue(threshold time.Time) []domain.Event
	ListEventsByTargetIP(ip string, from time.Time, to time.Time) []domain.Event
	ArchiveConvergedEvents(threshold time.Time, batchSize int) (int, error)
	SaveArchiveJob(job domain.ArchiveJob) (domain.ArchiveJob, error)
	GetArchiveJob(jobID string) (domain.ArchiveJob, bool)
	UpdateEvent(eventID string, patch map[string]any) (domain.Event, bool)

	AddMessage(m domain.Message) (domain.Message, error)
	ListMessages(eventID string) []domain.Message

	AddTask(t domain.Task) (domain.Task, error)
	UpdateTask(taskID string, patch map[string]any) (domain.Task, bool)
	ListTasks(eventID string) []domain.Task
	AddAction(a domain.Action) (domain.Action, error)
	UpdateAction(actionID string, patch map[string]any) (domain.Action, bool)
	ListActions(eventID string) []domain.Action
	AddCommand(c domain.Command) (domain.Command, error)
	UpdateCommand(commandID string, patch map[string]any) (domain.Command, bool)
	ListCommands(eventID string) []domain.Command
	AddExecution(e domain.Execution) (domain.Execution, error)
	ListExecutions(eventID string) []domain.Execution
	AddSummary(sm domain.Summary) (domain.Summary, error)
	ListSummaries(eventID string) []domain.Summary

	ReserveFingerprint(fp string) bool
	BindEventMap(fp, lyID, deepSOCID string)
	GetEventMap(fp string) (domain.EventMap, bool)

	GetCursor(name string) domain.SyncCursor
	SaveCursor(c domain.SyncCursor)

	AlreadyPushed(id string) bool
	SavePushedEvent(pe domain.PushedEvent)

	AddAuditLog(a domain.AuditLog) domain.AuditLog

	CreateAsset(a domain.Asset) (domain.Asset, error)
	GetAsset(id string) (domain.Asset, bool)
	ListAssets() []domain.Asset
	UpdateAsset(id string, patch map[string]any) (domain.Asset, bool)
	DeleteAsset(id string) bool

	SaveAssetReportSummary(sm domain.AssetReportSummary) (domain.AssetReportSummary, error)
	GetAssetReportSummary(assetID string, period string) (domain.AssetReportSummary, bool)
	ListAssetReportSummaries(assetID string) []domain.AssetReportSummary

	CreateAssetReportJob(job domain.AssetReportJob) (domain.AssetReportJob, error)
	UpdateAssetReportJob(jobID string, patch map[string]any) (domain.AssetReportJob, bool)
	GetAssetReportJob(jobID string) (domain.AssetReportJob, bool)
}

// EventQuery 事件列表服务端分页/过滤条件。
// Scope: today（默认，未归档）/ archive（按日归档）/ all（全量，全局搜索）。
type EventQuery struct {
	Scope     string
	Date      string // YYYY-MM-DD，Scope=archive 时必填
	Page      int
	PageSize  int
	Level     string
	Keyword   string
	Asset     string
	StartTime *time.Time
	EndTime   *time.Time
}

// EventPage 事件分页结果。
type EventPage struct {
	Items []domain.Event
	Total int
}
