package organize

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"
)

// NormalizeOrganizeAddress 规范化单位地址字段。
// 当 region_code 已设置时，保留 unit_detail_address 独立存储；否则合并到 address。
func NormalizeOrganizeAddress(item *model.Organize) {
	if item == nil {
		return
	}
	if strings.TrimSpace(item.RegionCode) != "" {
		return
	}
	addr := strings.TrimSpace(item.Address)
	detail := strings.TrimSpace(item.UnitDetailAddress)
	switch {
	case addr == "" && detail != "":
		item.Address = detail
	case addr != "" && detail != "" && addr != detail && !strings.Contains(addr, detail):
		item.Address = addr + " " + detail
	}
	item.UnitDetailAddress = ""
}

// NormalizeOrganizeUpdates 更新组织时规范化地址字段。
func NormalizeOrganizeUpdates(updates map[string]interface{}) {
	if updates == nil {
		return
	}
	if rc, ok := updates["region_code"].(string); ok && strings.TrimSpace(rc) != "" {
		sanitizeOrganizeCreditCodeInUpdates(updates)
		return
	}
	addr, _ := updates["address"].(string)
	detail, _ := updates["unit_detail_address"].(string)
	if strings.TrimSpace(addr) == "" && strings.TrimSpace(detail) != "" {
		updates["address"] = strings.TrimSpace(detail)
	} else if strings.TrimSpace(addr) != "" && strings.TrimSpace(detail) != "" {
		a := strings.TrimSpace(addr)
		d := strings.TrimSpace(detail)
		if a != d && !strings.Contains(a, d) {
			updates["address"] = a + " " + d
		}
	}
	updates["unit_detail_address"] = ""
	sanitizeOrganizeCreditCodeInUpdates(updates)
}

// sanitizeOrganizeCreditCodeInUpdates 空信用代码不参与更新，避免将 ” 写入触发 UNIQUE。
func sanitizeOrganizeCreditCodeInUpdates(updates map[string]interface{}) {
	if updates == nil {
		return
	}
	v, ok := updates["unified_social_credit_code"]
	if !ok {
		return
	}
	code := strings.TrimSpace(fmt.Sprint(v))
	if code == "" {
		delete(updates, "unified_social_credit_code")
		return
	}
	updates["unified_social_credit_code"] = code
}
