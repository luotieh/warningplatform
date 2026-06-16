package di

import (
	"strconv"

	"code.yt-security.com/public/access/identity"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

func (h *Handlers) registerUserListAPI(g *gin.RouterGroup) {
	g.GET("/system/users", h.listIAMUsers)
}

func (h *Handlers) listIAMUsers(c *gin.Context) {
	if h.IAM == nil || h.IAM.Identity == nil {
		web.Fail(c).Msg("IAM 未初始化").Send()
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "200"))
	keyword := c.Query("keyword")

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 200
	}

	query := identity.UserQuery{
		Index: page,
		Size:  pageSize,
	}
	if keyword != "" {
		query.UserName = keyword
	}

	result, err := h.IAM.Identity.ListUsers(c.Request.Context(), query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	type userItem struct {
		UserID     string `json:"user_id"`
		Account    string `json:"account"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		Phone      string `json:"phone"`
		OrganizeID string `json:"organize_id"`
	}

	items := make([]userItem, 0, len(result.Items))
	for _, u := range result.Items {
		items = append(items, userItem{
			UserID:     u.ID,
			Account:    u.UserName,
			Name:       u.NickName,
			Email:      u.Email,
			Phone:      u.Phone,
			OrganizeID: u.PrimaryOrganizeID,
		})
	}

	web.Succeed(c).List(result.Total, items).Send()
}
