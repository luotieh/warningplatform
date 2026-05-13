package sitemonitor

import (
	"vulnscan-backend/sitemonitor/contract"
)

type HandlerMonitor struct {
	svc contract.ServiceMonitor
}

func NewHandlerMonitor(svc contract.ServiceMonitor) *HandlerMonitor {
	return &HandlerMonitor{svc: svc}
}
