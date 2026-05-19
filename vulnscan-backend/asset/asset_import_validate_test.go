package asset

import (
	"strings"
	"testing"
)

func TestValidateImportRequiredFields(t *testing.T) {
	headerMap := map[string]int{
		"name": 0, "organize_name": 1, "asset_family": 2, "is_online": 3,
		"address": 4, "is_key": 5, "security_protection_level": 6,
	}
	row := []string{"测试系统", "", "IP资产", "是", "", "否", "无"}
	issues := validateImportRequiredFields(3, row, headerMap)
	if len(issues) < 2 {
		t.Fatalf("expected organize and address issues, got %v", issues)
	}
}

func TestIsImportIPv6Placeholder(t *testing.T) {
	if !isImportIPv6Placeholder("无") {
		t.Fatal("无 should be placeholder")
	}
}

func TestBuildImportFailedRows(t *testing.T) {
	rows := [][]string{
		{"group"},
		{"name", "organize_name", "address"},
		{"系统A", "单位1", ""},
	}
	headerMap := map[string]int{"name": 0, "organize_name": 1, "address": 2}
	issues := []assetImportIssue{
		{Row: 3, Field: "访问地址", Message: "不能为空"},
		{Row: 3, Field: "资产分类", Message: "不能为空"},
	}
	got := buildImportFailedRows(rows, headerMap, issues)
	if len(got) != 1 {
		t.Fatalf("expected 1 failed row, got %d", len(got))
	}
	if got[0].Name != "系统A" || got[0].OrganizeName != "单位1" {
		t.Fatalf("unexpected preview: %+v", got[0])
	}
	if !strings.Contains(got[0].ErrorSummary, "访问地址") {
		t.Fatalf("summary: %q", got[0].ErrorSummary)
	}
}
