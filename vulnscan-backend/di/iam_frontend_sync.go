package di

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/access/transport"
	"code.yt-security.com/public/core/web"
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
	if strings.EqualFold(h.Config.IAM.Mode, "local") {
		web.Resp(c, web.InternalError.SetMessage("本地认证模式不支持同步前端菜单到 IAM"))
		return
	}
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

	totalRefs, emptyRefs := countFrontendRefs(req.Items, 0, 0)
	slog.Info("[sync-frontends] 收到前端菜单", "total_items", countFrontendItems(req.Items), "backend_refs_total", totalRefs, "items_without_refs", emptyRefs)

	if err := h.IAM.SyncFrontends(ctx, req.Items); err != nil {
		slog.Error("[vulnscan] sync frontends to IAM failed", "err", err, "user", user.UserID)
		web.Resp(c, web.InternalError.SetError(err))
		return
	}
	web.Resp(c, web.Success)
}

func countFrontendItems(items []authorize.FrontendItem) int {
	n := len(items)
	for i := range items {
		n += countFrontendItems(items[i].Children)
	}
	return n
}

func countFrontendRefs(items []authorize.FrontendItem, refs, empty int) (int, int) {
	for i := range items {
		if len(items[i].BackendRefs) > 0 {
			refs += len(items[i].BackendRefs)
		} else if items[i].MenuType != 0 && items[i].Path != "" {
			empty++
			slog.Debug("[sync-frontends] 无 backend_refs", "name", items[i].Name, "title", items[i].Title, "path", items[i].Path, "menu_type", items[i].MenuType)
		}
		refs, empty = countFrontendRefs(items[i].Children, refs, empty)
	}
	return refs, empty
}

// dumpFrontendRefs 打印所有前端菜单项的 backend_refs（调试用）
func dumpFrontendRefs(items []authorize.FrontendItem, parentPath string) {
	for _, item := range items {
		p := parentPath + "/" + item.Path
		if len(item.BackendRefs) > 0 {
			slog.Debug("[sync-frontends] refs", "name", item.Name, "path", p, "refs", fmt.Sprintf("%v", item.BackendRefs))
		}
		dumpFrontendRefs(item.Children, p)
	}
}
