package oplog

import (
	"context"
	"fmt"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceOplog struct {
	db *db.DB
}

func NewServiceOplog(database *db.DB) *serviceOplog {
	return &serviceOplog{db: database}
}

func (s *serviceOplog) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceOplog) ByCircularId(ctx context.Context, circularId string) ([]model.CircularOperationLog, error) {
	if circularId == "" {
		return nil, fmt.Errorf("通报ID不能为空")
	}

	var logs []model.CircularOperationLog
	if err := s.session().WithContext(ctx).
		Where("circular_id = ?", circularId).
		Order("operation_time ASC").
		Find(&logs).Error; err != nil {
		return nil, err
	}

	return logs, nil
}
