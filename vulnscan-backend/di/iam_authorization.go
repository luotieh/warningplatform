package di

import (
	"net/http"
	"strings"

	authMiddleware "code.yt-security.com/public/access/auth/middleware"
	"github.com/gin-gonic/gin"
)

// loginOnlyAPIPrefixes 登录即可访问的路径前缀（任何 HTTP 方法）。
var loginOnlyAPIPrefixes = []string{
	"/api/system/dict",
	"/api/formdesign/",
	"/api/setting/",
	"/api/config/",
}

// loginOnlyGetPrefixes 仅 GET 方法登录即可访问的路径前缀（枚举/选项等只读接口）。
var loginOnlyGetPrefixes = []string{
	"/api/asset/region-scope",
	"/api/asset/industry-scope",
	"/api/asset/unit-type-scope",
	"/api/asset/family",
	"/api/asset/security_level",
	"/api/organize/",
}

// IAMAuthorization 使用 IAM verify 下发的 AllowedPaths 做接口级鉴权（与前端 backend_refs 同步一致）。
// 支撑类前缀仅要求登录，避免未单独分配权限码时页面不可用。
func (h *Handlers) IAMAuthorization() gin.HandlerFunc {
	sdkAuth := h.IAM.Middleware().Authorization()
	return func(c *gin.Context) {
		user, ok := authMiddleware.GetCurrentUser(c)
		if !ok || user.UserID == "" {
			sdkAuth(c)
			return
		}
		if user.IsPrivileged {
			c.Next()
			return
		}
		path := normalizeAPIPath(c)
		for _, prefix := range loginOnlyAPIPrefixes {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}
		if c.Request.Method == http.MethodGet {
			for _, prefix := range loginOnlyGetPrefixes {
				if strings.HasPrefix(path, prefix) {
					c.Next()
					return
				}
			}
		}
		sdkAuth(c)
	}
}
