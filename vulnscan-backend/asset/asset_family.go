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
	normalized := strings.TrimSpace(strings.ToLower(value))
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
