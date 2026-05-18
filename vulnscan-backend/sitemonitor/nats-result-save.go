package sitemonitor

import (
	"context"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func (s *NatsServiceImpl) saveSensitiveWordResult(tx *gorm.DB, execID, taskID string, r *model.MonitorSensitiveWordResult) error {
	return SaveSensitiveWordResult(tx, execID, taskID, r)
}

func (s *NatsServiceImpl) saveBaselineFromResult(tx *gorm.DB, executionID, url, agentID string, bu *model.MonitorBaselineUpdate) error {
	return SaveBaselineFromUpdate(context.Background(), tx, executionID, url, agentID, bu)
}

func (s *NatsServiceImpl) saveSensitiveFileResult(tx *gorm.DB, execID, taskID string, r *model.MonitorSensitiveFileResult) error {
	return SaveSensitiveFileResult(tx, execID, taskID, r)
}
