package asset

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestBuildAssetImportTemplateChoicesFallback(t *testing.T) {
	h := &HandlerAsset{}
	choices := h.buildAssetImportTemplateChoices(nil)

	if len(choices["asset_family"]) < 5 {
		t.Fatalf("asset_family choices too short: %v", choices["asset_family"])
	}
	if choices["is_online"][0] != "是" {
		t.Fatalf("unexpected is_online choices: %v", choices["is_online"])
	}
	sec := choices["security_protection_level"]
	if len(sec) == 0 || sec[0] != "无" {
		t.Fatalf("security_protection_level should start with 无: %v", sec)
	}
}

func TestApplyAssetImportDropdownValidations(t *testing.T) {
	f := excelize.NewFile()
	sheet := "资产导入"
	_ = f.SetSheetName("Sheet1", sheet)

	columns := []assetImportColumn{
		{Field: "asset_family", Title: "资产分类"},
		{Field: "is_online", Title: "是否联网"},
	}
	choices := map[string][]string{
		"asset_family": {"IP资产", "业务系统"},
		"is_online":    {"是", "否"},
	}
	dictRanges, err := writeAssetImportDictOptionsSheet(f, choices)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAssetImportDropdownValidations(f, sheet, columns, choices, dictRanges); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatal(err)
	}
	readBack, err := excelize.OpenReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer readBack.Close()
	dvs, err := readBack.GetDataValidations(sheet)
	if err != nil {
		t.Fatal(err)
	}
	if len(dvs) < 2 {
		t.Fatalf("expected data validations, got %d", len(dvs))
	}
}
