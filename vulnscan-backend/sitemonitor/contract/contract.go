package contract

import (
	"context"
	"fmt"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

// ErrDimensionBusy indicates a dimension already has an active execution.
// Callers (e.g. CronScheduler) can check for this to silently skip instead of logging a warning.
type ErrDimensionBusy struct {
	Dimension string
}

func (e *ErrDimensionBusy) Error() string {
	return fmt.Sprintf("维度 %s 已有执行中的记录", e.Dimension)
}

type PageReq struct {
	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

type WordLibraryUpdateReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type WordLibraryListReq struct {
	Name string `form:"name"`
	PageReq
}

type WordLibraryDetail struct {
	model.MonitorWordLibrary
	Categories []WordCategoryWithEntries `json:"categories"`
	TotalWords int64                     `json:"total_words"`
}

type WordCategoryWithEntries struct {
	model.MonitorWordCategory
	Entries    []model.MonitorWordEntry `json:"entries"`
	EntryCount int64                    `json:"entry_count"`
}

type WordCategoryUpdateReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type WordEntryListReq struct {
	CategoryID string `form:"category_id" binding:"required"`
	Word       string `form:"word"`
	PageReq
}

type FileLibraryUpdateReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type FileLibraryListReq struct {
	Name string `form:"name"`
	PageReq
}

type FileLibraryDetail struct {
	model.MonitorFileLibrary
	TotalFiles int64 `json:"total_files"`
}

type FileEntryListReq struct {
	LibraryID string `form:"library_id" binding:"required"`
	Path      string `form:"path"`
	PageReq
}

type TaskUpdateReq struct {
	TaskName            string         `json:"task_name"`
	Notes               string         `json:"notes"`
	Enabled             *bool          `json:"enabled"`
	TargetHomepage      string         `json:"target_homepage"`
	TargetDomain        string         `json:"target_domain"`
	TargetSubdomains    string         `json:"target_subdomains"`
	TargetIps           string         `json:"target_ips"`
	ScheduleEnabled     *bool          `json:"schedule_enabled"`
	ScheduleCron        string         `json:"schedule_cron"`
	ConfigAvailability  map[string]any `json:"config_availability"`
	ConfigDomainHijack  map[string]any `json:"config_domain_hijack"`
	ConfigTamper        map[string]any `json:"config_tamper"`
	ConfigSensitiveFile map[string]any `json:"config_sensitive_file"`
	ConfigSensitiveWord map[string]any `json:"config_sensitive_word"`
	ConfigBlacklink     map[string]any `json:"config_blacklink"`
}

type TaskListReq struct {
	Name           string `form:"name"`
	TargetHomepage string `form:"target_homepage"`
	Enabled        string `form:"enabled"`
	PageReq
}

type BatchUpdateConfigsReq struct {
	Ids                 []string       `json:"ids" binding:"required,min=1"`
	ConfigAvailability  map[string]any `json:"config_availability,omitempty"`
	ConfigDomainHijack  map[string]any `json:"config_domain_hijack,omitempty"`
	ConfigTamper        map[string]any `json:"config_tamper,omitempty"`
	ConfigSensitiveFile map[string]any `json:"config_sensitive_file,omitempty"`
	ConfigSensitiveWord map[string]any `json:"config_sensitive_word,omitempty"`
	ConfigBlacklink     map[string]any `json:"config_blacklink,omitempty"`
}

type ExecutionListReq struct {
	TargetID    string `form:"target_id"`
	PathTaskID  string `form:"path_task_id"`
	Dimension   string `form:"dimension"`
	Status      string `form:"status"`
	HasIssue    string `form:"has_issue"`
	Disposition string `form:"disposition"`
	TimeStart   string `form:"time_start"`
	TimeEnd     string `form:"time_end"`
	PageReq
}

type ExecutionDetail struct {
	model.MonitorExecution
	WordResult   *model.MonitorResultSensitiveWord         `json:"word_result,omitempty"`
	WordMatches  []model.MonitorResultSensitiveWordMatch   `json:"word_matches,omitempty"`
	FileResult   *model.MonitorResultSensitiveFile         `json:"file_result,omitempty"`
	FileFindings []model.MonitorResultSensitiveFileFinding `json:"file_findings,omitempty"`
	PerfBaseline *model.MonitorPerfBaseline                `json:"perf_baseline,omitempty"`
}

type TaskDimStat struct {
	Total        int64 `json:"total"`
	IssueCount   int64 `json:"issue_count"`
	PendingCount int64 `json:"pending_count"`
	ValidCount   int64 `json:"valid_count"`
}

type DashboardStats struct {
	TotalTargets     int64 `json:"total_targets"`
	EnabledTargets   int64 `json:"enabled_targets"`
	TotalPathTasks   int64 `json:"total_path_tasks"`
	EnabledPathTasks int64 `json:"enabled_path_tasks"`
	TotalExecutions  int64 `json:"total_executions"`
	IssueExecutions  int64 `json:"issue_executions"`
	OnlineAgents     int64 `json:"online_agents"`
	TotalAgents      int64 `json:"total_agents"`
}

type RuleDataSummary struct {
	ModuleKey   string `json:"module_key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	HasData     bool   `json:"has_data"`
	UpdatedAt   string `json:"updated_at"`
	RuleCount   int    `json:"rule_count"`
	Group       string `json:"group"`
	Icon        string `json:"icon"`
}

type ImportRowResult struct {
	Row      int    `json:"row"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Success  bool   `json:"success"`
	TargetID string `json:"target_id,omitempty"`
	TaskID   string `json:"task_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

type ImportStatus string

const (
	ImportStatusPending   ImportStatus = "pending"
	ImportStatusRunning   ImportStatus = "running"
	ImportStatusCompleted ImportStatus = "completed"
	ImportStatusFailed    ImportStatus = "failed"
)

type ImportResult struct {
	ID        string            `json:"id"`
	Status    ImportStatus      `json:"status"`
	Total     int               `json:"total"`
	Success   int               `json:"success"`
	Failed    int               `json:"failed"`
	Processed int               `json:"processed"`
	Error     string            `json:"error,omitempty"`
	Results   []ImportRowResult `json:"results"`
	CreatedAt string            `json:"created_at"`
}

type TaskTrendPoint struct {
	Time        string  `json:"time"`
	Dimension   string  `json:"dimension,omitempty"`
	Status      string  `json:"status,omitempty"`
	Disposition string  `json:"disposition,omitempty"`
	Available   bool    `json:"available"`
	StatusCode  int     `json:"status_code"`
	TotalMS     float64 `json:"total_ms"`
	DNSMS       float64 `json:"dns_ms"`
	TCPMS       float64 `json:"tcp_connect_ms"`
	TLSMS       float64 `json:"tls_handshake_ms"`
	TTFBMS      float64 `json:"ttfb_ms"`
	HasIssue    bool    `json:"has_issue"`
}

// TaskTrendQuery 路径任务趋势查询（支持按维度与筛选条件）。
type TaskTrendQuery struct {
	Hours       int
	Dimension   string
	HasIssue    string
	Disposition string
	Status      string
	TimeStart   string
	TimeEnd     string
}

type TaskTrendResp struct {
	TaskID     string           `json:"task_id"`
	TaskName   string           `json:"task_name"`
	URL        string           `json:"url"`
	Points     []TaskTrendPoint `json:"points"`
	Summary    TaskTrendSummary `json:"summary"`
	Dimensions []TaskDimBrief   `json:"dimensions"`
}

type TaskTrendSummary struct {
	TotalChecks        int64   `json:"total_checks"`
	SuccessCount       int64   `json:"success_count"`
	FailedCount        int64   `json:"failed_count"`
	AvailableCount     int64   `json:"available_count"`
	UnavailableCount   int64   `json:"unavailable_count"`
	AvailabilityPct    float64 `json:"availability_pct"`
	AvgResponseMS      float64 `json:"avg_response_ms"`
	MaxResponseMS      float64 `json:"max_response_ms"`
	MinResponseMS      float64 `json:"min_response_ms"`
	IssueCount         int64   `json:"issue_count"`
	NormalCount        int64   `json:"normal_count"`
	PendingDisposition int64   `json:"pending_disposition"`
}

type TaskDimBrief struct {
	Dimension    string `json:"dimension"`
	Total        int64  `json:"total"`
	SuccessCount int64  `json:"success_count"`
	FailedCount  int64  `json:"failed_count"`
	IssueCount   int64  `json:"issue_count"`
	LastStatus   string `json:"last_status"`
	LastTime     string `json:"last_time"`
}

type RunTaskSkip struct {
	Dimension string `json:"dimension"`
	Reason    string `json:"reason"`
}

type RunTaskOutcome struct {
	ExecutionIDs []string      `json:"execution_ids"`
	Skipped      []RunTaskSkip `json:"skipped,omitempty"`
}

type ServiceMonitor interface {
	CreateWordLibrary(ctx context.Context, lib *model.MonitorWordLibrary) error
	UpdateWordLibrary(ctx context.Context, id string, req WordLibraryUpdateReq) error
	DeleteWordLibrary(ctx context.Context, id string) error
	GetWordLibrary(ctx context.Context, id string) (*WordLibraryDetail, error)
	ListWordLibraries(ctx context.Context, req WordLibraryListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorWordLibrary, error)

	CreateWordCategory(ctx context.Context, cat *model.MonitorWordCategory) error
	UpdateWordCategory(ctx context.Context, id string, req WordCategoryUpdateReq) error
	DeleteWordCategory(ctx context.Context, id string) error
	ListWordCategories(ctx context.Context, libraryID string) ([]model.MonitorWordCategory, error)

	BatchCreateWordEntries(ctx context.Context, entries []model.MonitorWordEntry) error
	DeleteWordEntries(ctx context.Context, ids []int64) error
	ListWordEntries(ctx context.Context, req WordEntryListReq) (int64, []model.MonitorWordEntry, error)

	CreateFileLibrary(ctx context.Context, lib *model.MonitorFileLibrary) error
	UpdateFileLibrary(ctx context.Context, id string, req FileLibraryUpdateReq) error
	DeleteFileLibrary(ctx context.Context, id string) error
	GetFileLibrary(ctx context.Context, id string) (*FileLibraryDetail, error)
	ListFileLibraries(ctx context.Context, req FileLibraryListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorFileLibrary, error)

	BatchCreateFileEntries(ctx context.Context, entries []model.MonitorFileEntry) error
	DeleteFileEntries(ctx context.Context, ids []int64) error
	ListFileEntries(ctx context.Context, req FileEntryListReq) (int64, []model.MonitorFileEntry, error)
	CountFileEntryByPath(ctx context.Context, libraryID, path string, count *int64)

	ListDefaultConfigs(ctx context.Context) ([]model.MonitorDefaultConfig, error)
	GetDefaultConfig(ctx context.Context, dimension string) (*model.MonitorDefaultConfig, error)
	UpdateDefaultConfig(ctx context.Context, dimension string, configJSON map[string]any) error

	CreateTarget(ctx context.Context, t *model.MonitorTarget) error
	UpdateTarget(ctx context.Context, id string, req TargetUpdateReq) error
	DeleteTarget(ctx context.Context, id string) error
	BatchDeleteTargets(ctx context.Context, ids []string) error
	GetTarget(ctx context.Context, id string) (*model.MonitorTarget, error)
	ListTargets(ctx context.Context, req TargetListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorTarget, error)
	RunTarget(ctx context.Context, targetID string, dimensions []string) (*RunTaskOutcome, error)
	CreateTasksFromAssets(ctx context.Context, assetIDs []string) (*CreateTasksFromAssetsResp, []string, error)
	StartCrawl(ctx context.Context, targetID string, req CrawlStartReq) (*model.MonitorCrawlJob, error)
	GetCrawlJob(ctx context.Context, id string) (*model.MonitorCrawlJob, error)
	ApplyCrawlPaths(ctx context.Context, jobID string, req CrawlApplyReq) (int, error)

	CreatePathTask(ctx context.Context, pt *model.MonitorPathTask) error
	UpdatePathTask(ctx context.Context, id string, req PathTaskUpdateReq) error
	DeletePathTask(ctx context.Context, id string) error
	GetPathTask(ctx context.Context, id string) (*model.MonitorPathTask, error)
	ListPathTasks(ctx context.Context, req PathTaskListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorPathTask, error)
	RunPathTask(ctx context.Context, id string, dimensions []string) (*RunTaskOutcome, error)
	BatchDeletePathTasks(ctx context.Context, ids []string) error

	ListExecutions(ctx context.Context, req ExecutionListReq, scopes ...func(*gorm.DB) *gorm.DB) (int64, []model.MonitorExecution, error)
	GetExecutionDetail(ctx context.Context, id string) (*ExecutionDetail, error)
	GetEvidenceAsset(ctx context.Context, executionID, assetType string) ([]byte, string, error)
	DeleteExecution(ctx context.Context, id string) error
	BatchDeleteExecutions(ctx context.Context, ids []string) error
	UpdateDisposition(ctx context.Context, id, disposition, remark, username string) error
	BatchUpdateDisposition(ctx context.Context, ids []string, disposition, remark, username string) error
	GetDashboardStats(ctx context.Context) (*DashboardStats, error)
	GetTaskExecutionStats(ctx context.Context) (map[string]map[string]*TaskDimStat, error)
	GetTaskTrend(ctx context.Context, taskID string, q TaskTrendQuery) (*TaskTrendResp, error)

	ListAgents(ctx context.Context, scopes ...func(*gorm.DB) *gorm.DB) ([]model.MonitorAgent, error)
	SyncAgentRules(ctx context.Context, agentUUID string) (map[string]any, error)
	ShutdownAgent(ctx context.Context, agentUUID string) (map[string]any, error)
	DeleteAgent(ctx context.Context, agentUUID string) error

	GetAlertConfig(ctx context.Context) (*model.MonitorAlertConfig, error)
	UpdateAlertConfig(ctx context.Context, cfg *model.MonitorAlertConfig) error

	GenerateImportTemplate(ctx context.Context) ([]byte, error)
	ImportTasks(ctx context.Context, fileData []byte) (*ImportResult, error)
	GetImportResult(ctx context.Context, importID string) (*ImportResult, error)
	ExportImportResult(ctx context.Context, importID string) ([]byte, error)

	GetRuleData(ctx context.Context, moduleKey string) (*model.MonitorRuleData, error)
	PutRuleData(ctx context.Context, moduleKey string, data string) error
	ListRuleDataSummary(ctx context.Context) ([]RuleDataSummary, error)
	SyncAllRuleData(ctx context.Context) error
	GetDB() *db.DB

	FetchTaskMeta(ctx context.Context, url string) (title string, finalURL string, err error)
}

type NatsService interface {
	PublishTask(ctx context.Context, msg model.MonitorTaskMessage) error
	SyncWordLibraryToKV(ctx context.Context, libraryID string) error
	DeleteWordLibraryFromKV(ctx context.Context, libraryID string) error
	SyncFileLibraryToKV(ctx context.Context, libraryID string) error
	DeleteFileLibraryFromKV(ctx context.Context, libraryID string) error
	StartResultConsumer(ctx context.Context) error
	StartStatusSubscriber(ctx context.Context) error
	StartSchedulerSyncSubscriber(ctx context.Context, scheduler SchedulerSync) error
	BroadcastSchedulerSync(action string, taskID string)
	GetActiveBaseline(ctx context.Context, url string) (*model.MonitorBaseline, error)
	SaveBaselineFromAgent(ctx context.Context, tx *gorm.DB, executionID, url, agentID string, bu *model.MonitorBaselineUpdate) error
	GetLastSimhash(ctx context.Context, taskID string) string
	SyncRuleDataToKV(ctx context.Context, kvKey string, data []byte) error
	ListKVKeysByPrefix(ctx context.Context, prefix string) ([]string, error)
	DeleteKVKey(ctx context.Context, key string) error
	SendAgentCommand(ctx context.Context, agentUUID string, command string) (map[string]any, error)
	ObjGetGzip(ctx context.Context, key string) ([]byte, error)
	ObjGetRaw(ctx context.Context, key string) ([]byte, error)
	ObjDeleteSilent(ctx context.Context, key string)
	Close()
}

type SchedulerSync interface {
	SyncTargetFromDB(targetID string)
	SyncPathTaskFromDB(pathTaskID string)
	RemoveTarget(targetID string)
	RemovePathTask(pathTaskID string)
}
