package dispatch

import (
	"context"
	"fmt"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	dispatchContract "vulnscan-backend/dispatch/dispatch-contract"
	"vulnscan-backend/model"
)

type contactService struct {
	db *db.DB
}

func NewContactService(database *db.DB) *contactService {
	return &contactService{db: database}
}

func (s *contactService) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *contactService) List(ctx context.Context, q dispatchContract.ContactQuery, organizeID string) ([]model.DispatchContact, int64, error) {
	tx := s.session().WithContext(ctx).Model(&model.DispatchContact{})
	if organizeID != "" {
		tx = tx.Where("organize_id = ?", organizeID)
	}
	if q.Company != "" {
		tx = tx.Where("company = ?", q.Company)
	}
	if q.Keyword != "" {
		kw := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR company LIKE ? OR email LIKE ? OR phone LIKE ?", kw, kw, kw, kw)
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

	var items []model.DispatchContact
	if err := tx.Offset((page - 1) * size).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *contactService) GetByID(ctx context.Context, id string) (*model.DispatchContact, error) {
	var contact model.DispatchContact
	if err := s.session().WithContext(ctx).Where("id = ?", id).First(&contact).Error; err != nil {
		return nil, fmt.Errorf("联系人不存在")
	}
	return &contact, nil
}

func (s *contactService) Create(ctx context.Context, req dispatchContract.CreateContactReq, userID, organizeID string) (*model.DispatchContact, error) {
	contact := model.DispatchContact{
		ID:         ulid.GenerateID(),
		Name:       req.Name,
		Company:    req.Company,
		Role:       req.Role,
		Email:      req.Email,
		Phone:      req.Phone,
		Tags:       req.Tags,
		Note:       req.Note,
		CreatedBy:  userID,
		OrganizeID: organizeID,
	}
	if err := s.session().WithContext(ctx).Create(&contact).Error; err != nil {
		return nil, err
	}
	return &contact, nil
}

func (s *contactService) Update(ctx context.Context, id string, req dispatchContract.UpdateContactReq) error {
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Company != "" {
		updates["company"] = req.Company
	}
	if req.Role != "" {
		updates["role"] = req.Role
	}
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.Tags != nil {
		updates["tags"] = req.Tags
	}
	if req.Note != "" {
		updates["note"] = req.Note
	}
	if len(updates) == 0 {
		return nil
	}
	return s.session().WithContext(ctx).Model(&model.DispatchContact{}).Where("id = ?", id).Updates(updates).Error
}

func (s *contactService) Delete(ctx context.Context, id string) error {
	return s.session().WithContext(ctx).Where("id = ?", id).Delete(&model.DispatchContact{}).Error
}
