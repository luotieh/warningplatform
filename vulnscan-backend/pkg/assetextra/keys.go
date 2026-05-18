package assetextra

// 资产 extra JSON 中历史/约定键名。
const (
	KeyUnitLocationCode  = "unit_location_code"
	KeyUnitAddress       = "unit_address"
	KeyUnitType          = "unit_type"
	KeyRegionCode        = "region_code"
	KeyUnitDetailAddress = "unit_detail_address"
)

// UnitProfileKeys 单位档案字段：仅存于 vs_organize，不应写入资产 extra。
var UnitProfileKeys = []string{
	KeyUnitLocationCode,
	KeyUnitAddress,
	KeyUnitDetailAddress,
	KeyUnitType,
	"industry_category",
	"is_notification_member",
	"unified_social_credit_code",
	"leader_name",
	"leader_title",
	"responsible_department_name",
	"department_leader_name",
	"department_leader_title",
	"department_leader_phone",
	"contact_name",
	"contact_title",
	"contact_phone",
}

func IsUnitProfileKey(key string) bool {
	for _, k := range UnitProfileKeys {
		if k == key {
			return true
		}
	}
	return false
}
