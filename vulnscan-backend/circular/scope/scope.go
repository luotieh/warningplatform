package scope

import (
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

func GetOrganize(c *gin.Context) string {
	user, _ := iamsdk.GetCurrentUser(c)
	if user.OrganizeID != "" {
		return user.OrganizeID
	}
	return DefaultOrganizeID()
}
