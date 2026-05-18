package organize

import "vulnscan-backend/pkg/dberr"

func userFacingOrganizeError(err error) string {
	return dberr.UserFacing(err, "更新单位档案失败")
}
