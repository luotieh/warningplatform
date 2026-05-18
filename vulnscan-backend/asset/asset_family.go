package asset

import (
	"strings"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

var supportedAssetFamilies = []string{
	"ip",
	"domain_site",
	"business_system",
	"hardware",
	"software",
	"app",
	"mini_program",
	"official_account",
	"public_mailbox",
	"other",
}

// assetFamilyLabelAliases 导入模板常用中文标签（与 systemdict asset_family 默认项一致）。
var assetFamilyLabelAliases = map[string]string{
	"IP资产": "ip",
	"域名网站": "domain_site",
	"业务系统": "business_system",
	"硬件设备": "hardware",
	"软件资产": "software",
	"APP":  "app",
	"小程序":  "mini_program",
	"公众号":  "official_account",
	"公共邮箱": "public_mailbox",
	"其他":   "other",
}

var assetFamilyAliases = map[string]string{
	"ip":               "ip",
	"domain":           "domain_site",
	"domain_site":      "domain_site",
	"domainsite":       "domain_site",
	"website":          "domain_site",
	"site":             "domain_site",
	"business_system":  "business_system",
	"businesssystem":   "business_system",
	"hardware":         "hardware",
	"software":         "software",
	"app":              "app",
	"mini_program":     "mini_program",
	"miniprogram":      "mini_program",
	"official_account": "official_account",
	"officialaccount":  "official_account",
	"public_mailbox":   "public_mailbox",
	"publicmailbox":    "public_mailbox",
	"other":            "other",
}

func canonicalAssetFamily(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if canonical, ok := assetFamilyLabelAliases[trimmed]; ok {
		return canonical
	}
	normalized := strings.ToLower(trimmed)
	if normalized == "" {
		return ""
	}
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return assetFamilyAliases[normalized]
}

func normalizeAssetFamilyValue(assetFamily, systemType, assetType, domain, _ string, _ string) string {
	for _, candidate := range []string{assetFamily, systemType, assetType} {
		if normalized := canonicalAssetFamily(candidate); normalized != "" {
			return normalized
		}
	}
	if strings.TrimSpace(domain) != "" {
		return "domain_site"
	}
	return "ip"
}

func normalizeAssetFamily(item *model.Asset) {
	if item == nil {
		return
	}
	item.AssetFamily = normalizeAssetFamilyValue(
		item.AssetFamily,
		item.SystemType,
		item.Type,
		item.Domain,
		item.URL,
		item.Address,
	)
}

func normalizeAssetFamilies(items []model.Asset) {
	for i := range items {
		normalizeAssetFamily(&items[i])
	}
}

func applyAssetFamilyFilter(tx *gorm.DB, rawFamily string) *gorm.DB {
	family := canonicalAssetFamily(rawFamily)
	if family == "" {
		return tx.Where("asset_family = ?", rawFamily)
	}

	const assetFamilyExpr = "LOWER(REPLACE(COALESCE(asset_family, ''), '-', '_'))"
	const systemTypeExpr = "LOWER(REPLACE(COALESCE(system_type, ''), '-', '_'))"
	const typeExpr = "LOWER(REPLACE(COALESCE(type, ''), '-', '_'))"

	switch family {
	case "ip":
		return tx.Where(
			"("+assetFamilyExpr+" = ? OR ("+assetFamilyExpr+" = '' AND COALESCE(domain, '') = '' AND "+systemTypeExpr+" NOT IN ? AND "+typeExpr+" NOT IN ?))",
			family,
			supportedAssetFamilies,
			supportedAssetFamilies,
		)
	case "domain_site":
		return tx.Where(
			"("+assetFamilyExpr+" = ? OR ("+assetFamilyExpr+" = '' AND ("+systemTypeExpr+" = ? OR "+typeExpr+" = ? OR COALESCE(domain, '') <> '')))",
			family,
			family,
			family,
		)
	default:
		return tx.Where(
			"("+assetFamilyExpr+" = ? OR ("+assetFamilyExpr+" = '' AND ("+systemTypeExpr+" = ? OR "+typeExpr+" = ?)))",
			family,
			family,
			family,
		)
	}
}
