package organize

import (
	"strings"

	"vulnscan-backend/model"
)

// NormalizeOrganizeAddress 合并单位地址：主地址写入 address，清空 unit_detail_address。
func NormalizeOrganizeAddress(item *model.Organize) {
	if item == nil {
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

// NormalizeOrganizeUpdates 更新组织时合并地址字段。
func NormalizeOrganizeUpdates(updates map[string]interface{}) {
	if updates == nil {
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
}
