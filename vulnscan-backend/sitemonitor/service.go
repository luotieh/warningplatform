package sitemonitor

import (
	"context"
	"log/slog"
	"time"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceMonitor struct {
	db   *db.DB
	nats *NatsServiceImpl
}

func NewServiceMonitor(database *db.DB) *serviceMonitor {
	return &serviceMonitor{db: database}
}

func (s *serviceMonitor) GetDB() *db.DB { return s.db }

func (s *serviceMonitor) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func paginateQuery(query *gorm.DB, index, size int) *gorm.DB {
	if size <= 0 {
		size = 20
	}
	offset := 0
	if index > 0 && size > 0 {
		offset = (index - 1) * size
	}
	return query.Offset(offset).Limit(size)
}

// ══ KV 同步辅助（3次指数退避） ══

func (s *serviceMonitor) retryKVSync(ctx context.Context, fn func() error, label string) {
	if s.nats == nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(200<<uint(attempt-1)) * time.Millisecond)
		}
		if err := fn(); err != nil {
			slog.Warn("[Monitor] KV同步失败", "label", label, "attempt", attempt+1, "error", err)
			continue
		}
		return
	}
	slog.Error("[Monitor] KV同步最终失败", "label", label)
}
