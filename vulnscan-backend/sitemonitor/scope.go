package sitemonitor

import "code.yt-security.com/public/access/permission"

var monitorFieldMapping = permission.FieldMapping{
	UserIDColumn:       "created_by",
	OrganizeIDColumn:   "organize_id",
	DepartmentIDColumn: "",
}

var monitorExecutionFieldMapping = permission.FieldMapping{
	UserIDColumn:       "monitor_targets.created_by",
	OrganizeIDColumn:   "monitor_targets.organize_id",
	DepartmentIDColumn: "",
}
