package intel

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/core/generate/ulid"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type SubscriptionService struct {
	db      *gorm.DB
	matcher *VulnMatcher
}

func NewSubscriptionService(db *gorm.DB, matcher *VulnMatcher) *SubscriptionService {
	return &SubscriptionService{db: db, matcher: matcher}
}

func (s *SubscriptionService) MatchNewCVEs(entries []CVEEntry) {
	if len(entries) == 0 {
		return
	}

	var subs []model.IntelSubscription
	s.db.Where("enabled = ?", true).Find(&subs)
	if len(subs) == 0 {
		return
	}

	now := time.Now()
	var notifications []model.Notification

	for i := range subs {
		sub := &subs[i]
		matched := s.matchSubscription(sub, entries)
		if len(matched) == 0 {
			continue
		}

		for _, cve := range matched {
			n := model.Notification{
				ID:       ulid.GenerateID(),
				UserID:   sub.UserID,
				Type:     model.NotifyTypeIntelMatch,
				Title:    fmt.Sprintf("[情报订阅] %s: %s", sub.Name, cve.ID),
				Content:  fmt.Sprintf("订阅规则「%s」匹配到新漏洞 %s (%s, CVSS %.1f): %s", sub.Name, cve.ID, cve.Severity, cve.CVSSScore, truncate(cve.Description, 200)),
				Link:     fmt.Sprintf("/intel?cve=%s", cve.ID),
				Severity: cve.Severity,
			}
			notifications = append(notifications, n)
		}

		sub.LastMatchAt = &now
		sub.MatchCount += len(matched)
		s.db.Model(sub).Updates(map[string]interface{}{
			"last_match_at": sub.LastMatchAt,
			"match_count":   sub.MatchCount,
		})
	}

	if len(notifications) > 0 {
		if err := s.db.CreateInBatches(notifications, 100).Error; err != nil {
			slog.Error("批量创建情报订阅通知失败", "error", err)
		} else {
			slog.Info("[+] 情报订阅推送完成", "notifications", len(notifications))
		}
	}
}

func (s *SubscriptionService) matchSubscription(sub *model.IntelSubscription, entries []CVEEntry) []CVEEntry {
	var matched []CVEEntry

	for _, cve := range entries {
		if sub.OnlyExploit && !cve.HasExploit {
			continue
		}
		if sub.OnlyKEV && !cve.InKEV {
			continue
		}

		if len(sub.Severities) > 0 {
			found := false
			for _, sev := range sub.Severities {
				if strings.EqualFold(cve.Severity, sev) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		matchedByRule := false

		if len(sub.Products) > 0 {
			for _, product := range sub.Products {
				productLower := strings.ToLower(product)
				for _, cpe := range cve.CPE {
					if strings.Contains(strings.ToLower(cpe), productLower) {
						matchedByRule = true
						break
					}
				}
				if matchedByRule {
					break
				}
			}
		}

		if !matchedByRule && len(sub.Keywords) > 0 {
			descLower := strings.ToLower(cve.Description)
			idLower := strings.ToLower(cve.ID)
			for _, kw := range sub.Keywords {
				kwLower := strings.ToLower(kw)
				if strings.Contains(descLower, kwLower) || strings.Contains(idLower, kwLower) {
					matchedByRule = true
					break
				}
			}
		}

		if !matchedByRule && len(sub.Products) == 0 && len(sub.Keywords) == 0 {
			matchedByRule = true
		}

		if matchedByRule {
			matched = append(matched, cve)
		}
	}

	return matched
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// --- HTTP Handlers ---

func (h *Handler) ListSubscriptions(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	var items []model.IntelSubscription
	tx := h.db.Model(&model.IntelSubscription{})
	if userID != "" {
		tx = tx.Where("user_id = ?", userID)
	}
	tx.Order("created_at DESC").Find(&items)

	web.Succeed(c).Data(items).Send()
}

func (h *Handler) CreateSubscription(c *gin.Context) {
	user, _ := middleware.GetCurrentUser(c)
	userID := ""
	if user != nil {
		userID = user.UserID
	}

	req, ok := web.BindJSON[CreateSubscriptionReq](c)
	if !ok {
		return
	}

	sub := model.IntelSubscription{
		ID:          ulid.GenerateID(),
		UserID:      userID,
		Name:        req.Name,
		Products:    model.StringArray(req.Products),
		Keywords:    model.StringArray(req.Keywords),
		Severities:  model.StringArray(req.Severities),
		OnlyExploit: req.OnlyExploit,
		OnlyKEV:     req.OnlyKEV,
		Enabled:     true,
	}

	if err := h.db.Create(&sub).Error; err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(sub).Send()
}

func (h *Handler) UpdateSubscription(c *gin.Context) {
	id := c.Param("id")

	var sub model.IntelSubscription
	if err := h.db.Where("id = ?", id).First(&sub).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	req, ok := web.BindJSON[UpdateSubscriptionReq](c)
	if !ok {
		return
	}

	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Products != nil {
		updates["products"] = model.StringArray(req.Products)
	}
	if req.Keywords != nil {
		updates["keywords"] = model.StringArray(req.Keywords)
	}
	if req.Severities != nil {
		updates["severities"] = model.StringArray(req.Severities)
	}
	if req.OnlyExploit != nil {
		updates["only_exploit"] = *req.OnlyExploit
	}
	if req.OnlyKEV != nil {
		updates["only_kev"] = *req.OnlyKEV
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if len(updates) > 0 {
		h.db.Model(&sub).Updates(updates)
	}

	h.db.Where("id = ?", id).First(&sub)
	web.Succeed(c).Data(sub).Send()
}

func (h *Handler) DeleteSubscription(c *gin.Context) {
	id := c.Param("id")
	h.db.Where("id = ?", id).Delete(&model.IntelSubscription{})
	web.Succeed(c).Send()
}

func (h *Handler) TestSubscription(c *gin.Context) {
	id := c.Param("id")

	var sub model.IntelSubscription
	if err := h.db.Where("id = ?", id).First(&sub).Error; err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}

	subSvc := NewSubscriptionService(h.db, h.matcher)
	allCVEs := make([]CVEEntry, 0, len(h.matcher.cveDB))
	for _, cve := range h.matcher.cveDB {
		allCVEs = append(allCVEs, *cve)
	}

	matched := subSvc.matchSubscription(&sub, allCVEs)
	if len(matched) > 20 {
		matched = matched[:20]
	}

	web.Succeed(c).Data(gin.H{
		"subscription": sub,
		"matched":      len(matched),
		"preview":      matched,
	}).Send()
}
