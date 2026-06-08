package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type serviceWorkflow struct {
	db *db.DB
}

func NewServiceWorkflow(database *db.DB) *serviceWorkflow {
	return &serviceWorkflow{db: database}
}

func (s *serviceWorkflow) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceWorkflow) List(req ac.WorkflowListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Workflow, int64, error) {
	var items []model.Workflow
	var count int64

	q := s.session().Model(&model.Workflow{}).Scopes(scopes...)
	if req.Enabled != nil {
		q = q.Where("enabled = ?", *req.Enabled)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := req.Page, req.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

func (s *serviceWorkflow) Create(item *model.Workflow) error {
	if item.ID == "" {
		item.ID = ulid.GenerateID()
	}
	return s.session().Create(item).Error
}

func (s *serviceWorkflow) Update(id string, data map[string]interface{}) error {
	return s.session().Model(&model.Workflow{}).Where("id = ?", id).Updates(data).Error
}

func (s *serviceWorkflow) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Workflow{}).Error
}

func (s *serviceWorkflow) ListExecutions(req ac.ExecutionListReq, scopes ...func(*gorm.DB) *gorm.DB) ([]model.WorkflowExecution, int64, error) {
	var items []model.WorkflowExecution
	var count int64

	q := s.session().Model(&model.WorkflowExecution{}).Scopes(scopes...)
	if req.WorkflowID != "" {
		q = q.Where("workflow_id = ?", req.WorkflowID)
	}
	if req.Status != "" {
		q = q.Where("status = ?", req.Status)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := req.Page, req.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	err := q.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error
	return items, count, err
}

var _ ac.ServiceWorkflow = (*serviceWorkflow)(nil)
