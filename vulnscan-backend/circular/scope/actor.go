package scope

import (
	iamsdk "code.yt-security.com/public/access"
	"github.com/gin-gonic/gin"
)

// Actor 表示当前操作者（IAM 用户或系统账号）。
type Actor struct {
	ID   string
	Name string
}

// ActorFromContext 从 Gin 上下文解析当前登录用户。
func ActorFromContext(c *gin.Context) Actor {
	user, ok := iamsdk.GetCurrentUser(c)
	if !ok || user.UserID == "" {
		return SystemActor()
	}
	name := user.Account
	if name == "" {
		name = user.UserID
	}
	return Actor{ID: user.UserID, Name: name}
}

// SystemActor 表示系统自动操作。
func SystemActor() Actor {
	return Actor{ID: "system", Name: "系统"}
}

// ResolveOrganize 按优先级选取组织标识，均空时回退默认组织。
func ResolveOrganize(candidates ...string) string {
	for _, o := range candidates {
		if o != "" {
			return o
		}
	}
	return DefaultOrganizeID()
}

// DefaultOrganizeID 开发/未绑定 IAM 组织时的兜底值。
func DefaultOrganizeID() string {
	return "yt-networks-security"
}
