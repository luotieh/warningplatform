package assetmgrContract

import "vulnscan-backend/model"

// ── 生命周期 ──

type LifecycleListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	AssetID  string `form:"asset_id"`
}

type TransitionReq struct {
	AssetID string `json:"asset_id" binding:"required"`
	ToState string `json:"to_state" binding:"required"`
	Remark  string `json:"remark"`
}

type ServiceLifecycle interface {
	ListTransitions(req LifecycleListReq) ([]model.AssetLifecycle, int64, error)
	Transition(assetID, toState, operator, remark string) error
}

// ── 合规 ──

type ComplianceItemReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	AssetID  string `form:"asset_id"`
	ItemType string `form:"item_type"`
	Status   string `form:"status"`
}

type ServiceComplianceItem interface {
	List(req ComplianceItemReq) ([]model.AssetCompliance, int64, error)
	Create(item *model.AssetCompliance) error
	Update(id int64, data map[string]interface{}) error
	Delete(id int64) error
}

// ── 责任人 ──

type ResponsibleListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	AssetID  string `form:"asset_id"`
}

type ServiceResponsible interface {
	List(req ResponsibleListReq) ([]model.AssetResponsible, int64, error)
	Create(item *model.AssetResponsible) error
	Update(id int64, data map[string]interface{}) error
	Delete(id int64) error
}

// ── 风险评分 ──

type RiskListReq struct {
	Page     int     `form:"page"`
	PageSize int     `form:"page_size"`
	MinScore float64 `form:"min_score"`
}

type ServiceRisk interface {
	List(req RiskListReq) ([]model.AssetRiskScore, int64, error)
	GetByAssetID(assetID string) (*model.AssetRiskScore, error)
	Recalculate(assetID string) error
	RecalculateAll() (int, error)
}

// ── 告警 ──

type AlertListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	AssetID  string `form:"asset_id"`
	Status   string `form:"status"`
	Severity string `form:"severity"`
}

type ServiceAlert interface {
	List(req AlertListReq) ([]model.Alert, int64, error)
	Create(item *model.Alert) error
	Ack(id string, ackedBy string) error
	Resolve(id string) error
}

// ── 审核 ──

type VerifyListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	AssetID  string `form:"asset_id"`
	Status   string `form:"status"`
}

type ReviewReq struct {
	AssetID      string `json:"asset_id" binding:"required"`
	ReviewStatus string `json:"review_status" binding:"required"`
	ReviewRemark string `json:"review_remark"`
}

type ServiceVerify interface {
	List(req VerifyListReq) ([]model.AssetVerify, int64, error)
	Submit(item *model.AssetVerify) error
	Review(id string, status, remark, reviewer string) error
}

type VerifyTaskListReq struct {
	Page              int    `form:"page"`
	PageSize          int    `form:"page_size"`
	AssetID           string `form:"asset_id"`
	Status            string `form:"status"`
	Keyword           string `form:"keyword"`
	OwnerOrganizeID   string `form:"owner_organize_id"`
	CurrentOrganizeID string `form:"current_organize_id"`
	SourceType        string `form:"source_type"`
}

type VerifyTaskCreateReq struct {
	AssetIDs         []string `json:"asset_ids" binding:"required"`
	BatchID          string   `json:"batch_id"`
	SourceType       string   `json:"source_type"`
	TargetOrganizeID string   `json:"target_organize_id"`
	Remark           string   `json:"remark"`
}

type VerifyTaskActionReq struct {
	TargetOrganizeID string `json:"target_organize_id"`
	VerifyResult     string `json:"verify_result"`
	RejectReason     string `json:"reject_reason"`
	Remark           string `json:"remark"`
}

type VerifyTaskResp struct {
	model.AssetVerifyTask
	AssetName  string `json:"asset_name"`
	SystemName string `json:"system_name"`
	Address    string `json:"address"`
	AssetType  string `json:"asset_type"`
	DataNumber string `json:"data_number"`
}

type VerifyTaskLogsReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	TaskID   string `form:"task_id"`
	AssetID  string `form:"asset_id"`
}

type ArchiveListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	AssetID    string `form:"asset_id"`
	Keyword    string `form:"keyword"`
	OrganizeID string `form:"organize_id"`
	BatchID    string `form:"batch_id"`
}

type ServiceVerifyTask interface {
	ListTasks(req VerifyTaskListReq) ([]VerifyTaskResp, int64, error)
	CreateTasks(req VerifyTaskCreateReq, operator, organizeID string) ([]model.AssetVerifyTask, error)
	Receive(id, operator, organizeID, remark string) error
	Confirm(id, operator, remark string) error
	Reject(id, operator, reason, remark string) error
	Forward(id, targetOrganizeID, operator, remark string) error
	Return(id, operator, remark string) error
	Archive(id, operator, remark string) error
	Reactivate(id, operator, remark string) error
	ListLogs(req VerifyTaskLogsReq) ([]model.AssetVerifyOplog, int64, error)
	ListArchives(req ArchiveListReq) ([]model.AssetArchiveSnapshot, int64, error)
	GetArchive(id string) (*model.AssetArchiveSnapshot, error)
}

// ── 合规模板 ──

type TemplateListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Standard string `form:"standard"`
}

type ServiceComplianceTemplate interface {
	List(req TemplateListReq) ([]model.ComplianceTemplate, int64, error)
	GetByID(id int64) (*model.ComplianceTemplate, error)
	Create(item *model.ComplianceTemplate) error
	Update(id int64, data map[string]interface{}) error
	Delete(id int64) error
	ListItems(templateID int64) ([]model.ComplianceTemplateItem, error)
	CreateItem(item *model.ComplianceTemplateItem) error
}

// ── 合规检查结果 ──

type CheckResultListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	AssetID    string `form:"asset_id"`
	TemplateID int64  `form:"template_id"`
	Status     string `form:"status"`
}

type ServiceCheckResult interface {
	List(req CheckResultListReq) ([]model.ComplianceCheckResult, int64, error)
	Upsert(item *model.ComplianceCheckResult) error
}

// ── 集成 ──

type IntSourceListReq struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Module   string `form:"module"`
}

type ServiceIntegration interface {
	ListSources(req IntSourceListReq) ([]model.IntegrationSource, int64, error)
	CreateSource(item *model.IntegrationSource) error
	UpdateSource(id int64, data map[string]interface{}) error
	DeleteSource(id int64) error
}

// ── 工作流 ──

type WorkflowListReq struct {
	Page     int   `form:"page"`
	PageSize int   `form:"page_size"`
	Enabled  *bool `form:"enabled"`
}

type ExecutionListReq struct {
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
	WorkflowID string `form:"workflow_id"`
	Status     string `form:"status"`
}

type ServiceWorkflow interface {
	List(req WorkflowListReq) ([]model.Workflow, int64, error)
	Create(item *model.Workflow) error
	Update(id string, data map[string]interface{}) error
	Delete(id string) error
	ListExecutions(req ExecutionListReq) ([]model.WorkflowExecution, int64, error)
}
