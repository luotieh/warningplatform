// Package aihub 提供 AI 能力中心，聚合所有 AI 增强服务。
//
// 统一管理 AI 服务的生命周期，提供统一的 HTTP API 入口。
package aihub

import (
	"vulnscan-backend/knowledge/aicompliance"
	"vulnscan-backend/knowledge/aicrawl"
	"vulnscan-backend/knowledge/aifingerprint"
	"vulnscan-backend/knowledge/aipayload"
	"vulnscan-backend/knowledge/aipoc"
	"vulnscan-backend/knowledge/aiquery"
	"vulnscan-backend/knowledge/aireport"
	"vulnscan-backend/knowledge/aistrategy"
	"vulnscan-backend/knowledge/aiverify"

	"code.yt-security.com/public/access/ai"
)

// Hub AI 能力中心。
type Hub struct {
	Fingerprint *aifingerprint.EnhancedService
	Verify      *aiverify.Service
	Payload     *aipayload.Service
	Crawl       *aicrawl.Service
	Report      *aireport.Service
	Strategy    *aistrategy.Service
	Query       *aiquery.Service
	POC         *aipoc.Service
	Compliance  *aicompliance.Service
}

// NewHub 创建 AI 能力中心。
func NewHub(aiSvc ai.Service, model string) *Hub {
	return &Hub{
		Fingerprint: aifingerprint.NewEnhancedService(aiSvc, model),
		Verify:      aiverify.NewService(aiSvc, model),
		Payload:     aipayload.NewService(aiSvc, model),
		Crawl:       aicrawl.NewService(aiSvc, model),
		Report:      aireport.NewService(aiSvc, model),
		Strategy:    aistrategy.NewService(aiSvc, model),
		Query:       aiquery.NewService(aiSvc, model),
		POC:         aipoc.NewService(aiSvc, model),
		Compliance:  aicompliance.NewService(aiSvc, model),
	}
}
