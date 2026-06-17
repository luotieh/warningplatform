package sitemonitor

import (
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/db"
)

type HandlerMonitor struct {
	svc contract.ServiceMonitor
	db  *db.DB
}

func NewHandlerMonitor(svc contract.ServiceMonitor) *HandlerMonitor {
	return &HandlerMonitor{svc: svc}
}
