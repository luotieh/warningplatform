package asset

import (
	"fmt"
	"strings"

	"vulnscan-backend/systemdict"

	"github.com/xuri/excelize/v2"
	"gorm.io/gorm"
)

const (
	assetImportTemplateDataRows = 2000
	assetImportDictOptionsSheet = "字典选项"
)

var assetImportBoolDropdown = []string{"是", "否"}

// assetImportDictDropdownFields 下拉数据来自系统数据字典（dict_id）。
var assetImportDictDropdownFields = map[string]string{
	"asset_family":              "asset_family",
	"security_protection_level": "asset_security_level",
}

var assetImportBoolDropdownFields = map[string]bool{
	"is_online": true,
	"is_key":    true,
}

func (h *HandlerAsset) buildAssetImportTemplateChoices(sess *gorm.DB) map[string][]string {
	choices := map[string][]string{
		"is_online": assetImportBoolDropdown,
		"is_key":    assetImportBoolDropdown,
	}
	for field, dictID := range assetImportDictDropdownFields {
		labels := systemdict.EnabledDictLabels(sess, dictID)
		if field == "security_protection_level" {
			labels = appendSecurityLevelNoneOption(labels)
		}
		choices[field] = labels
	}
	return choices
}

func appendSecurityLevelNoneOption(labels []string) []string {
	out := []string{"无"}
	seen := map[string]bool{"无": true}
	for _, label := range labels {
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	return out
}

// writeAssetImportDictOptionsSheet 将当前系统字典项写入「字典选项」sheet，并返回各字段对应的下拉区域公式。
func writeAssetImportDictOptionsSheet(f *excelize.File, choices map[string][]string) (map[string]string, error) {
	sheet := assetImportDictOptionsSheet
	if idx, _ := f.GetSheetIndex(sheet); idx < 0 {
		if _, err := f.NewSheet(sheet); err != nil {
			return nil, err
		}
	}
	ranges := map[string]string{}
	specs := []struct {
		field string
		col   string
		title string
	}{
		{"asset_family", "A", "资产分类（系统字典 asset_family）"},
		{"security_protection_level", "C", "安全保护等级（系统字典 asset_security_level）"},
	}
	for _, spec := range specs {
		labels := choices[spec.field]
		if len(labels) == 0 {
			continue
		}
		_ = f.SetCellValue(sheet, spec.col+"1", spec.title)
		for i, label := range labels {
			cell := fmt.Sprintf("%s%d", spec.col, i+2)
			_ = f.SetCellValue(sheet, cell, label)
		}
		endRow := len(labels) + 1
		ranges[spec.field] = fmt.Sprintf("'%s'!$%s$2:$%s$%d", sheet, spec.col, spec.col, endRow)
	}
	_ = f.SetColWidth(sheet, "A", "A", 22)
	_ = f.SetColWidth(sheet, "C", "C", 28)
	return ranges, nil
}

func applyAssetImportDropdownValidations(
	f *excelize.File,
	dataSheet string,
	columns []assetImportColumn,
	choices map[string][]string,
	dictRanges map[string]string,
) error {
	const firstDataRow = 3
	lastDataRow := firstDataRow + assetImportTemplateDataRows - 1

	for colIdx, col := range columns {
		colName, err := excelize.ColumnNumberToName(colIdx + 1)
		if err != nil {
			return err
		}
		sqref := fmt.Sprintf("%s%d:%s%d", colName, firstDataRow, colName, lastDataRow)

		if dictID, isDict := assetImportDictDropdownFields[col.Field]; isDict {
			if err := applyDictFieldDropdown(f, dataSheet, sqref, col.Field, dictID, choices, dictRanges); err != nil {
				return err
			}
			continue
		}
		if !assetImportBoolDropdownFields[col.Field] {
			continue
		}
		opts := choices[col.Field]
		if len(opts) == 0 {
			continue
		}
		if err := applyInlineDropdown(f, dataSheet, sqref, opts); err != nil {
			return err
		}
	}
	return nil
}

func applyDictFieldDropdown(
	f *excelize.File,
	dataSheet, sqref, field, dictID string,
	choices map[string][]string,
	dictRanges map[string]string,
) error {
	opts := choices[field]
	if len(opts) == 0 {
		return nil
	}
	dv := excelize.NewDataValidation(true)
	dv.Sqref = sqref
	dv.AllowBlank = true

	rangeRef := dictRanges[field]
	if rangeRef != "" {
		formula := "=" + rangeRef
		if err := dv.SetDropList([]string{formula}); err != nil {
			return err
		}
	} else if err := dv.SetDropList(opts); err != nil {
		return err
	}

	hint := fmt.Sprintf("选项来自系统数据字典「%s」", dictID)
	dv.SetInput(hint, "请从下拉列表中选择")
	dv.SetError(excelize.DataValidationErrorStyleStop, "无效选项", "请从下拉中选择系统字典已配置的值")
	return f.AddDataValidation(dataSheet, dv)
}

func applyInlineDropdown(f *excelize.File, sheet, sqref string, opts []string) error {
	dv := excelize.NewDataValidation(true)
	dv.Sqref = sqref
	if err := dv.SetDropList(opts); err != nil {
		return err
	}
	dv.SetInput("请从下拉列表中选择", "")
	dv.SetError(excelize.DataValidationErrorStyleStop, "无效选项", "请填写："+strings.Join(opts, "、"))
	return f.AddDataValidation(sheet, dv)
}
