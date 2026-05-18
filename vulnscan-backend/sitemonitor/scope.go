package sitemonitor

import "code.yt-security.com/public/sdk/permission"

var monitorFieldMapping = permission.FieldMapping{
	UserIDColumn:       "created_by",
	OrganizeIDColumn:   "organize_id",
	DepartmentIDColumn: "",
}

var monitorExecutionFieldMapping = permission.FieldMapping{
	UserIDColumn:       "monitor_tasks.created_by",
	OrganizeIDColumn:   "monitor_tasks.organize_id",
	DepartmentIDColumn: "",
}
