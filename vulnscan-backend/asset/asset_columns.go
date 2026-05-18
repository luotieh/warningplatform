package asset

import "strings"

func isConstructionOrgColumn(field string) bool {
	return field == "construction_org" || strings.HasPrefix(field, "construction_org_")
}

func filterAssetColumns(columns []assetImportColumn, keep func(string) bool) []assetImportColumn {
	out := make([]assetImportColumn, 0, len(columns))
	for _, col := range columns {
		if keep(col.Field) {
			out = append(out, col)
		}
	}
	return out
}

// assetLedgerColumnsVisible 面向模板/导出的列定义（不含建设单位；地域不落模板列）。
func assetLedgerColumnsVisible() []assetImportColumn {
	return filterAssetColumns(assetLedgerColumns, func(field string) bool {
		return !isConstructionOrgColumn(field)
	})
}
