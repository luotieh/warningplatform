package di

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"code.yt-security.com/public/sdk/middleware"
	"code.yt-security.com/public/sdk/transport"
	"github.com/gin-gonic/gin"
)

// registerPrivilegedFrontendSync 注册菜单同步代理（使用应用 client_credentials，不经用户 token）。
//
// SDK 默认的 POST /frontends/sync 会把用户 access token 转发到 IAM，
// 非特权用户会触发 IAM 12403（需 IAM「前端菜单同步」后端权限）。
// 本路由仅供子系统初始化：要求当前用户为特权账号（IAM 管理员/超级管理员角色）。
func (h *Handlers) registerPrivilegedFrontendSync(g *gin.RouterGroup) {
	g.POST("/system/iam/sync-frontends", h.syncFrontendsWithServiceToken)
}

func (h *Handlers) syncFrontendsWithServiceToken(c *gin.Context) {
	user, ok := middleware.GetCurrentUser(c)
	if !ok || user.UserID == "" {
		web.Resp(c, web.Unauthorized.SetMessage("未登录"))
		return
	}
	if !user.IsPrivileged {
		web.Resp(c, web.Forbidden.SetMessage(
			"仅特权账号可同步菜单到 IAM，请使用 IAM 管理员登录，或在 IAM 后台为当前角色分配「前端菜单同步」权限",
		))
		return
	}

	var req struct {
		Items []authorize.FrontendItem `json:"items" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired.SetError(err))
		return
	}
	if h.Config.IAM.ClientID == "" {
		web.Resp(c, web.InternalError.SetError(errors.New("iam client_id not configured")))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// 清空用户 token，强制 SDK 使用 client_credentials（scope=sdk）访问 IAM
	ctx = transport.WithForwardedToken(ctx, "")

	if err := h.IAM.Authorize.SyncFrontends(ctx, h.Config.IAM.ClientID, req.Items); err != nil {
		slog.Error("[vulnscan] sync frontends to IAM failed", "err", err, "user", user.UserID)
		web.Resp(c, web.InternalError.SetError(err))
		return
	}
	web.Resp(c, web.Success)
}
