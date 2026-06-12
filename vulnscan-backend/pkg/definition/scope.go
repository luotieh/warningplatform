package definition

import (
	iamsdk "code.yt-security.com/public/access"
	authMiddleware "code.yt-security.com/public/access/auth/middleware"
	"code.yt-security.com/public/access/permission"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// VulnscanFieldMapping is the project-wide default field mapping for IAM data-scope.
// All tables in this project use "created_by" (not the SDK default "creator_id").
var VulnscanFieldMapping = permission.FieldMapping{
	UserIDColumn:       "created_by",
	OrganizeIDColumn:   "organize_id",
	DepartmentIDColumn: "",
}

// VerifyTaskFieldMapping maps AssetVerifyTask columns for IAM data-scope.
var VerifyTaskFieldMapping = permission.FieldMapping{
	UserIDColumn:       "t.created_by",
	OrganizeIDColumn:   "t.owner_organize_id",
	DepartmentIDColumn: "",
}

// SafeDataFilterScope wraps iamsdk.DataFilterScopeStatic with a privileged-user
// bypass: privileged (super-admin) users see all data regardless of organize_id.
func SafeDataFilterScope(c *gin.Context, mapping permission.FieldMapping) func(*gorm.DB) *gorm.DB {
	if user, ok := authMiddleware.GetCurrentUser(c); ok && user.IsPrivileged {
		return func(db *gorm.DB) *gorm.DB { return db }
	}
	return iamsdk.DataFilterScopeStatic(c, mapping)
}
