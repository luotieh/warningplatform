package di

import (
	"strings"

	"code.yt-security.com/public/sdk/middleware"
	"github.com/gin-gonic/gin"
)

// 登录即可访问的业务支撑接口（须在 SyncBackends 注册；建议后续在 IAM 标记 authenticated）。
var loginOnlyAPIPrefixes = []string{
	"/api/systemdict/",
	"/api/formdesign/",
	"/api/setting/",
	"/api/config/",
}

// IAMAuthorization 使用 IAM verify 下发的 AllowedPaths 做接口级鉴权（与前端 backend_refs 同步一致）。
// 支撑类前缀仍仅要求登录，避免未单独分配权限码时配置页不可用。
func (h *Handlers) IAMAuthorization() gin.HandlerFunc {
	sdkAuth := h.IAM.Middleware().Authorization()
	return func(c *gin.Context) {
		user, ok := middleware.GetCurrentUser(c)
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
		sdkAuth(c)
	}
}
