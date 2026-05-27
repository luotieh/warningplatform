package definition

import "code.yt-security.com/public/sdk/permission"

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
