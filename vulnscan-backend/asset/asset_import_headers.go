package asset

import (
	"strings"
	"sync"
)

var (
	assetImportTitleAliasOnce  sync.Once
	assetImportTitleAliases    map[string]string
	assetGroupedTitleAliasOnce sync.Once
	assetGroupedTitleAliases   map[string]map[string]string
)

// assetImportExportStatColumns 仅导出表头，与 assetExportColumns 统计列一致。
var assetImportExportStatColumns = []assetImportColumn{
	{Field: "risk_score", Group: "导出统计信息", Title: "风险分"},
	{Field: "vuln_count", Group: "导出统计信息", Title: "漏洞数"},
	{Field: "status", Group: "导出统计信息", Title: "状态"},
	{Field: "created_at", Group: "导出统计信息", Title: "创建时间"},
}

// assetImportLegacyTitleAliases 兼容旧版/外部模板表头，不与 assetLedgerColumns 重复维护业务列名。
var assetImportLegacyTitleAliases = map[string]string{
	"资产名称": "name", "名称": "name", "system_name": "name",
	"地址": "address", "访问url": "address", "访问 url": "address", "网址": "url",
	"资产类型": "type", "系统类型": "system_type", "编号": "data_number",
	"关键信息基础设施": "is_key", "是否关键资产": "is_key",
	"保护等级": "security_protection_level", "安全防护等级": "security_protection_level", "等保等级": "security_protection_level",
	"等保证号": "filing_cert_number", "备案证明编号": "filing_cert_number",
	"icp备案": "icp_filing_number", "公网安备": "public_security_filing",
	"资产所属单位id": "organize_id", "所属单位id": "organize_id",
	"建设单位": "construction_org", "建设单位id": "construction_org", "construction_org_id": "construction_org",
	"建设单位所在地":    "construction_org_location",
	"建设单位详细地址":   "construction_org_address",
	"建设单位负责人及职务": "construction_org_charge_person", "建设单位负责人": "construction_org_charge_person",
	"建设单位联系电话":    "construction_org_charge_phone",
	"建设单位公网安备备案号": "construction_org_security_filing",
	"运维单位":        "operation_org", "运维单位id": "operation_org", "operation_org_id": "operation_org",
	"数据来源": "data_source",
	"责任人":  "responsible_user_name",
	"标签":   "tags",
	"单位地址": "unit_address", "单位详细地址": "unit_address", "unit_detail_address": "unit_address",
	"分管领导姓名":    "leader_name",
	"分管领导职务/职称": "leader_title",
	"责任部门名称":    "responsible_department_name",
	"责任部门负责人姓名": "department_leader_name",
	"负责人职务/职称":  "department_leader_title",
	"负责人电话":     "department_leader_phone",
	"上级单位":      "parent_organize_name",
	"备注":        "remark",
}

func assetImportTitleAliasMap() map[string]string {
	assetImportTitleAliasOnce.Do(func() {
		assetImportTitleAliases = buildAssetImportTitleAliases()
	})
	return assetImportTitleAliases
}

func ledgerTitleUseCount() map[string]int {
	counts := make(map[string]int, len(assetLedgerColumns))
	for _, col := range assetLedgerColumns {
		counts[normalizeHeader(col.Title)]++
	}
	return counts
}

func buildAssetImportTitleAliases() map[string]string {
	aliases := make(map[string]string, len(assetLedgerColumns)+32)
	titleCounts := ledgerTitleUseCount()
	for _, col := range assetLedgerColumns {
		if titleCounts[normalizeHeader(col.Title)] == 1 {
			registerColumnTitleAlias(aliases, col.Title, col.Field)
		}
		setImportTitleAlias(aliases, normalizeHeader(col.Field), col.Field)
	}
	for _, col := range assetImportExportStatColumns {
		registerColumnTitleAlias(aliases, col.Title, col.Field)
	}
	for title, field := range assetImportLegacyTitleAliases {
		registerColumnTitleAlias(aliases, title, field)
	}
	return aliases
}

func registerColumnTitleAlias(aliases map[string]string, title, field string) {
	title = strings.TrimSpace(title)
	field = strings.TrimSpace(field)
	if field == "" {
		return
	}
	if title != "" {
		setImportTitleAlias(aliases, normalizeHeader(title), field)
	}
	setImportTitleAlias(aliases, normalizeHeader(field), field)
}

func setImportTitleAlias(aliases map[string]string, key, field string) {
	if key == "" || field == "" {
		return
	}
	if _, exists := aliases[key]; exists {
		return
	}
	aliases[key] = field
}

func assetImportGroupedTitleAliasMap() map[string]map[string]string {
	assetGroupedTitleAliasOnce.Do(func() {
		assetGroupedTitleAliases = buildAssetImportGroupedTitleAliases()
	})
	return assetGroupedTitleAliases
}

func buildAssetImportGroupedTitleAliases() map[string]map[string]string {
	groupKey := func(name string) string { return normalizeHeader(name) }
	out := map[string]map[string]string{
		groupKey("系统建设单位基本情况"): buildConstructionOrgGroupedAliases(),
		groupKey("系统运维单位基本情况"): {},
	}
	for _, col := range assetLedgerColumns {
		g := groupKey(col.Group)
		sub, ok := out[g]
		if !ok || sub == nil {
			continue
		}
		registerColumnTitleAlias(sub, col.Title, col.Field)
	}
	registerOperationOrgGroupedShortAliases(out[groupKey("系统运维单位基本情况")])
	return out
}

func buildConstructionOrgGroupedAliases() map[string]string {
	aliases := make(map[string]string, 12)
	registerColumnTitleAlias(aliases, "建设单位名称", "construction_org")
	registerColumnTitleAlias(aliases, "单位名称", "construction_org")
	registerColumnTitleAlias(aliases, "名称", "construction_org")
	registerColumnTitleAlias(aliases, "所在地", "construction_org_location")
	registerColumnTitleAlias(aliases, "详细地址", "construction_org_address")
	registerColumnTitleAlias(aliases, "负责人及职务", "construction_org_charge_person")
	registerColumnTitleAlias(aliases, "负责人", "construction_org_charge_person")
	registerColumnTitleAlias(aliases, "联系电话", "construction_org_charge_phone")
	registerColumnTitleAlias(aliases, "公网安备备案号", "construction_org_security_filing")
	return aliases
}

func registerOperationOrgGroupedShortAliases(aliases map[string]string) {
	if aliases == nil {
		return
	}
	registerColumnTitleAlias(aliases, "单位名称", "operation_org")
	registerColumnTitleAlias(aliases, "名称", "operation_org")
	registerColumnTitleAlias(aliases, "负责人", "operation_org_charge_person")
}

func buildHeaderMap(headers []string) map[string]int {
	aliases := assetImportTitleAliasMap()
	m := make(map[string]int, len(headers))
	for i, h := range headers {
		key := normalizeHeader(h)
		if field, ok := aliases[key]; ok {
			m[field] = i
		}
	}
	return m
}

func buildGroupedHeaderMap(groupRow, fieldRow []string) map[string]int {
	globalAliases := assetImportTitleAliasMap()
	groupAliases := assetImportGroupedTitleAliasMap()
	m := make(map[string]int, len(fieldRow))

	currentGroup := ""
	for i, title := range fieldRow {
		if i < len(groupRow) {
			if group := normalizeHeader(groupRow[i]); group != "" {
				currentGroup = group
			}
		}
		fieldTitle := normalizeHeader(title)
		field, ok := resolveGroupedImportHeaderField(currentGroup, fieldTitle, groupAliases, globalAliases)
		if ok {
			m[field] = i
		}
	}
	return m
}

func resolveGroupedImportHeaderField(
	currentGroup, fieldTitle string,
	groupAliases map[string]map[string]string,
	globalAliases map[string]string,
) (string, bool) {
	if aliases := groupAliases[currentGroup]; aliases != nil {
		if field, ok := aliases[fieldTitle]; ok {
			return field, true
		}
	}
	field, ok := globalAliases[fieldTitle]
	return field, ok
}
