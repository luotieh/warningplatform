package di

import (
	"net/http"
	"strings"

	"code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

const ctxKeyAccessCodes = "vulnscan_access_codes"

// 已废弃：请使用 di/iam_authorization.go（SDK Authorization + IAM AllowedPaths）。
// 保留本文件仅供对照，不再挂载到路由。
//
// 业务 API 鉴权（唯一例外清单，无独立配置文件）
//
// 路由分组见 handlers.go：
//   · apiAuthenticated：/me、/auth、/identity（SDK 代理 IAM）→ 不经过本中间件
//   · apiAuthorized：其余业务 API → 本中间件
//
// 判定顺序：
//   1. 特权用户 → 放行
//   2. 支撑前缀（任意方法，仅登录）→ systemdict / formdesign / setting / config
//   3. 跨模块只读 GET → 见 crossModuleReadGETPrefixes（组织/扫描支撑/流水线/标签/首页/报告等）
//   4. 默认：/api/{模块}/* 须在 IAM 勾选对应菜单；若同步了按钮权限码则再匹配 list/create 等

var supportAnyMethodPrefixes = []string{
	"/api/systemdict/",
	"/api/formdesign/",
	"/api/setting/",
	"/api/config/",
}

var supportReadGETExact = []string{
	"/api/notify/unread-count",
}

// crossModuleReadGETPrefixes 多模块页面共用的只读 API（有 task 菜单也会调 scan/pipeline/report 等）。
var crossModuleReadGETPrefixes = []string{
	"/api/organize",
	"/api/pipeline",
	"/api/tagging",
	"/api/scan",
	"/api/dashboard",
	"/api/report",
}

var methodActions = map[string][]string{
	http.MethodGet:    {"list", "read", "export"},
	http.MethodPost:   {"create", "import", "export"},
	http.MethodPut:    {"update"},
	http.MethodPatch:  {"update"},
	http.MethodDelete: {"delete"},
}

func (h *Handlers) ModuleAuthorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := middleware.GetCurrentUser(c)
		if !ok || user.UserID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "authentication required"})
			return
		}
		if user.IsPrivileged {
			c.Next()
			return
		}

		path := normalizeAPIPath(c)
		method := c.Request.Method

		for _, p := range supportAnyMethodPrefixes {
			if strings.HasPrefix(path, p) {
				c.Next()
				return
			}
		}
		if isCrossModuleRead(path, method) {
			c.Next()
			return
		}

		module := apiModuleFromPath(path)
		if module == "" {
			c.Next()
			return
		}

		codes, err := h.loadAccessCodes(c)
		if err != nil {
			web.Resp(c, web.InternalError.SetError(err))
			c.Abort()
			return
		}
		if !hasModuleGrant(codes, module) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "无权访问模块「" + module + "」，请在 IAM 角色中勾选对应菜单",
			})
			return
		}
		if moduleHasButtonPerms(codes, module) && !methodAllowedByModule(codes, module, method) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "模块「" + module + "」缺少当前操作权限（如 list/create）",
			})
			return
		}
		c.Next()
	}
}

func normalizeAPIPath(c *gin.Context) string {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	return strings.TrimSuffix(path, "/")
}

func (h *Handlers) loadAccessCodes(c *gin.Context) ([]string, error) {
	if v, ok := c.Get(ctxKeyAccessCodes); ok {
		if codes, ok := v.([]string); ok {
			return codes, nil
		}
	}
	codes, err := h.IAM.MeAccessCodesFromGin(c)
	if err != nil {
		return nil, err
	}
	c.Set(ctxKeyAccessCodes, codes)
	return codes, nil
}

// isCrossModuleRead 多模块共用的只读接口（不要求拥有该路径第一段模块的菜单）。
func isCrossModuleRead(path, method string) bool {
	if !isReadMethod(method) {
		return false
	}
	for _, exact := range supportReadGETExact {
		if path == exact {
			return true
		}
	}
	for _, prefix := range crossModuleReadGETPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isReadMethod(method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	return m == http.MethodGet || m == http.MethodHead
}

func apiModuleFromPath(path string) string {
	path = strings.TrimPrefix(path, "/api/")
	if path == "" {
		return ""
	}
	if i := strings.Index(path, "/"); i >= 0 {
		return path[:i]
	}
	return path
}

func hasModuleGrant(codes []string, module string) bool {
	menuPath := "/" + module
	prefix := module + ":"
	for _, code := range codes {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		if code == menuPath || strings.HasPrefix(code, menuPath+"/") || strings.HasSuffix(code, menuPath) {
			return true
		}
		if code == module || strings.HasPrefix(code, prefix) {
			return true
		}
	}
	return false
}

func moduleHasButtonPerms(codes []string, module string) bool {
	prefix := module + ":"
	for _, code := range codes {
		if strings.HasPrefix(code, prefix) {
			return true
		}
	}
	return false
}

func methodAllowedByModule(codes []string, module string, method string) bool {
	actions, ok := methodActions[strings.ToUpper(method)]
	if !ok {
		return true
	}
	set := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	prefix := module + ":"
	for _, act := range actions {
		if _, ok := set[prefix+act]; ok {
			return true
		}
	}
	return false
}
