package asset

import "code.yt-security.com/public/sdk/permission"

// assetFieldMapping aligns IAM data-scope columns with local asset tables.
var assetFieldMapping = permission.FieldMapping{
	UserIDColumn:       "created_by",
	OrganizeIDColumn:   "organize_id",
	DepartmentIDColumn: "",
}
