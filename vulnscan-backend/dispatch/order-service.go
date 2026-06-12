package dispatch

import (
	"context"
	"fmt"
	"time"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	dispatchContract "vulnscan-backend/dispatch/dispatch-contract"
	"vulnscan-backend/model"
)

type orderService struct {
	db *db.DB
}

func NewOrderService(database *db.DB) *orderService {
	return &orderService{db: database}
}

func (s *orderService) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *orderService) List(ctx context.Context, q dispatchContract.OrderQuery, organizeID string) ([]model.DispatchOrder, int64, error) {
	tx := s.session().WithContext(ctx).Model(&model.DispatchOrder{})
	if organizeID != "" {
		tx = tx.Where("organize_id = ?", organizeID)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}
	if q.Type != "" {
		tx = tx.Where("type = ?", q.Type)
	}
	if q.Priority > 0 {
		tx = tx.Where("priority = ?", q.Priority)
	}
	if q.Keyword != "" {
		kw := "%" + q.Keyword + "%"
		tx = tx.Where("title LIKE ? OR code LIKE ? OR assignee_name LIKE ?", kw, kw, kw)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	page, size := q.Page, q.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}

	var items []model.DispatchOrder
	if err := tx.Offset((page - 1) * size).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *orderService) GetByID(ctx context.Context, id string) (*model.DispatchOrder, error) {
	var order model.DispatchOrder
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&order).Error; err != nil {
		return nil, fmt.Errorf("派发单不存在")
	}
	return &order, nil
}

func (s *orderService) Create(ctx context.Context, req dispatchContract.CreateOrderReq, userID, organizeID string) (*model.DispatchOrder, error) {
	now := time.Now()
	code := fmt.Sprintf("DP-%s-%03d", now.Format("20060102"), now.UnixMilli()%1000)

	order := model.DispatchOrder{
		ID:              ulid.GenerateID(),
		Code:            code,
		Title:           req.Title,
		Description:     req.Description,
		Type:            req.Type,
		Priority:        req.Priority,
		Status:          model.DispatchStatusDraft,
		SourceType:      req.SourceType,
		SourceID:        req.SourceID,
		SourceTitle:     req.SourceTitle,
		AssigneeType:    req.AssigneeType,
		AssigneeID:      req.AssigneeID,
		AssigneeName:    req.AssigneeName,
		AssigneeContact: req.AssigneeContact,
		Attachments:     req.Attachments,
		CreatedBy:       userID,
		OrganizeID:      organizeID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if order.Priority <= 0 {
		order.Priority = 3
	}
	if req.Deadline != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", req.Deadline); err == nil {
			order.Deadline = &t
		} else if t, err := time.Parse("2006-01-02", req.Deadline); err == nil {
			order.Deadline = &t
		}
	}

	if order.AssigneeName != "" {
		order.Status = model.DispatchStatusPending
	}

	if err := s.session().WithContext(ctx).Create(&order).Error; err != nil {
		return nil, err
	}

	s.writeLog(ctx, order.ID, "create", userID, "创建派发单: "+order.Title, nil)
	if order.Status == model.DispatchStatusPending {
		s.writeLog(ctx, order.ID, "assign", userID,
			fmt.Sprintf("指派给 %s (%s)", order.AssigneeName, order.AssigneeType), nil)
	}

	return &order, nil
}

func (s *orderService) Cancel(ctx context.Context, id, userID string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status == model.DispatchStatusCompleted || order.Status == model.DispatchStatusCancelled {
		return fmt.Errorf("当前状态不允许取消")
	}
	if err := s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).
		Updates(map[string]any{"status": model.DispatchStatusCancelled, "updated_at": time.Now()}).Error; err != nil {
		return err
	}
	s.writeLog(ctx, id, "cancel", userID, "取消派发单", nil)
	return nil
}

func (s *orderService) Assign(ctx context.Context, id string, req dispatchContract.AssignReq, userID string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status != model.DispatchStatusDraft && order.Status != model.DispatchStatusRejected {
		return fmt.Errorf("当前状态不允许指派")
	}

	updates := map[string]any{
		"assignee_type":    req.AssigneeType,
		"assignee_id":      req.AssigneeID,
		"assignee_name":    req.AssigneeName,
		"assignee_contact": req.AssigneeContact,
		"status":           model.DispatchStatusPending,
		"updated_at":       time.Now(),
	}
	if req.Deadline != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", req.Deadline); err == nil {
			updates["deadline"] = &t
		}
	}

	if err := s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	s.writeLog(ctx, id, "assign", userID,
		fmt.Sprintf("指派给 %s (%s)", req.AssigneeName, req.AssigneeType), nil)
	return nil
}

func (s *orderService) Accept(ctx context.Context, id, userID string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status != model.DispatchStatusPending {
		return fmt.Errorf("当前状态不允许接收")
	}
	now := time.Now()
	if err := s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).
		Updates(map[string]any{
			"status":      model.DispatchStatusInProgress,
			"accepted_at": &now,
			"updated_at":  now,
		}).Error; err != nil {
		return err
	}
	s.writeLog(ctx, id, "accept", userID, "接收派发单", nil)
	return nil
}

func (s *orderService) Reject(ctx context.Context, id, userID, reason string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status != model.DispatchStatusPending {
		return fmt.Errorf("当前状态不允许拒绝")
	}
	if err := s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).
		Updates(map[string]any{
			"status":        model.DispatchStatusRejected,
			"reject_reason": reason,
			"updated_at":    time.Now(),
		}).Error; err != nil {
		return err
	}
	s.writeLog(ctx, id, "reject", userID, "拒绝接收: "+reason, nil)
	return nil
}

func (s *orderService) SubmitResult(ctx context.Context, id string, req dispatchContract.SubmitResultReq, userID string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status != model.DispatchStatusInProgress {
		return fmt.Errorf("当前状态不允许提交结果")
	}
	now := time.Now()
	if err := s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).
		Updates(map[string]any{
			"status":       model.DispatchStatusSubmitted,
			"result":       req.Result,
			"result_data":  req.ResultData,
			"attachments":  req.Attachments,
			"submitted_at": &now,
			"updated_at":   now,
		}).Error; err != nil {
		return err
	}
	s.writeLog(ctx, id, "submit", userID, "提交处理结果", nil)
	return nil
}

func (s *orderService) Review(ctx context.Context, id string, req dispatchContract.ReviewReq, userID string) error {
	order, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if order.Status != model.DispatchStatusSubmitted {
		return fmt.Errorf("当前状态不允许审核")
	}
	now := time.Now()
	updates := map[string]any{
		"reviewer_id":    userID,
		"review_comment": req.Comment,
		"reviewed_at":    &now,
		"updated_at":     now,
	}
	if req.Approved {
		updates["status"] = model.DispatchStatusCompleted
		updates["completed_at"] = &now
		s.writeLog(ctx, id, "review_pass", userID, "审核通过: "+req.Comment, nil)
	} else {
		updates["status"] = model.DispatchStatusInProgress
		s.writeLog(ctx, id, "review_reject", userID, "审核驳回: "+req.Comment, nil)
	}
	return s.session().WithContext(ctx).Model(&model.DispatchOrder{}).Where("id = ?", id).Updates(updates).Error
}

func (s *orderService) GetOplogs(ctx context.Context, orderID string) ([]model.DispatchOplog, error) {
	var logs []model.DispatchOplog
	err := s.session().WithContext(ctx).Where("order_id = ?", orderID).Order("created_at ASC").Find(&logs).Error
	return logs, err
}

func (s *orderService) Stats(ctx context.Context, organizeID string) (*dispatchContract.StatsOverview, error) {
	stats := &dispatchContract.StatsOverview{
		ByStatus:   make(map[string]int),
		ByType:     make(map[string]int),
		ByPriority: make(map[string]int),
	}

	tx := s.session().WithContext(ctx).Model(&model.DispatchOrder{})
	if organizeID != "" {
		tx = tx.Where("organize_id = ?", organizeID)
	}
	tx.Count(&stats.Total)

	type kv struct {
		Key   string `gorm:"column:key"`
		Count int    `gorm:"column:count"`
	}

	var statusRows []kv
	s.session().WithContext(ctx).Model(&model.DispatchOrder{}).
		Select("status as `key`, count(*) as `count`").
		Group("status").Find(&statusRows)
	for _, r := range statusRows {
		stats.ByStatus[r.Key] = r.Count
	}

	var typeRows []kv
	s.session().WithContext(ctx).Model(&model.DispatchOrder{}).
		Select("type as `key`, count(*) as `count`").
		Group("type").Find(&typeRows)
	for _, r := range typeRows {
		stats.ByType[r.Key] = r.Count
	}

	var overdueCount int64
	s.session().WithContext(ctx).Model(&model.DispatchOrder{}).
		Where("deadline IS NOT NULL AND deadline < ? AND status NOT IN ?",
			time.Now(), []string{model.DispatchStatusCompleted, model.DispatchStatusCancelled}).
		Count(&overdueCount)
	stats.Overdue = int(overdueCount)

	return stats, nil
}

func (s *orderService) writeLog(ctx context.Context, orderID, action, operator, content string, data model.JSONMap) {
	log := model.DispatchOplog{
		OrderID:   orderID,
		Action:    action,
		Operator:  operator,
		Content:   content,
		Data:      data,
		CreatedAt: time.Now(),
	}
	_ = s.session().WithContext(ctx).Create(&log).Error
}
