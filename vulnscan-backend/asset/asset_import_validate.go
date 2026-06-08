package asset

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"code.yt-security.com/public/core/web"
)

// assetImportIssue 描述单行导入问题，供接口返回与前端展示。
type assetImportIssue struct {
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// assetImportFailedRow 导入失败行预览（供前端表格展示问题行）。
type assetImportFailedRow struct {
	Row          int                `json:"row"`
	Name         string             `json:"name"`
	OrganizeName string             `json:"organize_name"`
	Address      string             `json:"address"`
	AssetFamily  string             `json:"asset_family"`
	IsOnline     string             `json:"is_online,omitempty"`
	ErrorSummary string             `json:"error_summary"`
	Issues       []assetImportIssue `json:"issues"`
}

const importIssueMaxDisplay = 20

var assetImportColumnTitleByField map[string]string

func init() {
	assetImportColumnTitleByField = make(map[string]string, len(assetLedgerColumns))
	for _, col := range assetLedgerColumns {
		assetImportColumnTitleByField[col.Field] = col.Title
	}
}

func assetImportColumnTitle(field string) string {
	if t, ok := assetImportColumnTitleByField[field]; ok {
		return t
	}
	return field
}

func importIssue(row int, field, message string) assetImportIssue {
	return assetImportIssue{
		Row:     row,
		Field:   strings.TrimSpace(field),
		Message: strings.TrimSpace(message),
	}
}

func importIssueErr(row int, field string, err error) assetImportIssue {
	if err == nil {
		return importIssue(row, field, "校验失败")
	}
	msg := importUserFacingError(err)
	if strings.TrimSpace(field) == "" {
		return importIssue(row, "", msg)
	}
	return importIssue(row, field, msg)
}

func formatImportIssue(iss assetImportIssue) string {
	if iss.Field != "" {
		return fmt.Sprintf("第 %d 行【%s】：%s", iss.Row, iss.Field, iss.Message)
	}
	return formatImportRowError(iss.Row, errors.New(iss.Message))
}

func formatImportIssues(issues []assetImportIssue) string {
	if len(issues) == 0 {
		return "导入校验未通过"
	}
	if len(issues) == 1 {
		return formatImportIssue(issues[0])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "导入校验未通过，共 %d 处问题：\n", len(issues))
	limit := len(issues)
	if limit > importIssueMaxDisplay {
		limit = importIssueMaxDisplay
	}
	for i := 0; i < limit; i++ {
		b.WriteString(formatImportIssue(issues[i]))
		b.WriteByte('\n')
	}
	if len(issues) > importIssueMaxDisplay {
		fmt.Fprintf(&b, "…还有 %d 处未列出", len(issues)-importIssueMaxDisplay)
	}
	return strings.TrimSpace(b.String())
}

func summarizeImportIssues(issues []assetImportIssue) string {
	parts := make([]string, 0, len(issues))
	for _, iss := range issues {
		if iss.Field != "" {
			parts = append(parts, fmt.Sprintf("【%s】%s", iss.Field, iss.Message))
		} else {
			parts = append(parts, iss.Message)
		}
	}
	return strings.Join(parts, "；")
}

func importRowAtLine(rows [][]string, lineNum int) []string {
	if lineNum < 1 || lineNum > len(rows) {
		return nil
	}
	return rows[lineNum-1]
}

func buildImportFailedRows(allRows [][]string, headerMap map[string]int, issues []assetImportIssue) []assetImportFailedRow {
	byRow := make(map[int][]assetImportIssue, len(issues))
	for _, iss := range issues {
		byRow[iss.Row] = append(byRow[iss.Row], iss)
	}
	result := make([]assetImportFailedRow, 0, len(byRow))
	for rowNum, rowIssues := range byRow {
		excelRow := importRowAtLine(allRows, rowNum)
		preview := assetImportFailedRow{
			Row:          rowNum,
			Name:         getCell(excelRow, headerMap, "name"),
			OrganizeName: getCell(excelRow, headerMap, "organize_name"),
			Address:      getCell(excelRow, headerMap, "address"),
			AssetFamily:  getCell(excelRow, headerMap, "asset_family"),
			IsOnline:     getCell(excelRow, headerMap, "is_online"),
			Issues:       rowIssues,
			ErrorSummary: summarizeImportIssues(rowIssues),
		}
		if preview.Name == "" && preview.Address != "" {
			preview.Name = preview.Address
		}
		result = append(result, preview)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Row < result[j].Row })
	return result
}

func formatImportFailureBrief(issueCount, rowCount int) string {
	if rowCount > 0 {
		return fmt.Sprintf("导入校验未通过：共 %d 处问题，涉及 %d 行", issueCount, rowCount)
	}
	return fmt.Sprintf("导入校验未通过：共 %d 处问题", issueCount)
}

func respondImportValidationFailed(c *gin.Context, allRows [][]string, headerMap map[string]int, issues []assetImportIssue) {
	failedRows := buildImportFailedRows(allRows, headerMap, issues)
	// 业务失败但 HTTP 200，避免前端 axios 丢弃响应体导致无法展示问题行。
	web.Fail(c).HTTP(http.StatusOK).Msg(formatImportFailureBrief(len(issues), len(failedRows))).Data(gin.H{
		"errors":      issues,
		"error_count": len(issues),
		"failed_rows": failedRows,
	}).Send()
}

func isImportDataRow(row []string, headerMap map[string]int) bool {
	return strings.TrimSpace(getCell(row, headerMap, "name")) != "" ||
		strings.TrimSpace(getCell(row, headerMap, "address")) != ""
}

func validateImportRequiredFields(rowNum int, row []string, headerMap map[string]int) []assetImportIssue {
	if !isImportDataRow(row, headerMap) {
		return nil
	}
	var issues []assetImportIssue
	orgID := strings.TrimSpace(getCell(row, headerMap, "organize_id"))
	orgName := strings.TrimSpace(getCell(row, headerMap, "organize_name"))
	if orgID == "" && orgName == "" {
		issues = append(issues, importIssue(rowNum, assetImportColumnTitle("organize_name"), "请填写单位名称或所属单位 ID"))
	}
	if strings.TrimSpace(getCell(row, headerMap, "address")) == "" {
		issues = append(issues, importIssue(rowNum, assetImportColumnTitle("address"), "不能为空"))
	}
	for _, col := range assetImportColumns {
		if !col.Required {
			continue
		}
		switch col.Field {
		case "name", "organize_name", "address", "ipv6":
			continue
		}
		val := strings.TrimSpace(getCell(row, headerMap, col.Field))
		if col.Field == "ipv6" && isImportIPv6Placeholder(val) {
			continue
		}
		if val == "" {
			issues = append(issues, importIssue(rowNum, col.Title, "不能为空"))
		}
	}
	return issues
}

func isImportIPv6Placeholder(val string) bool {
	switch strings.TrimSpace(val) {
	case "", "无", "无ipv6", "无 ipv6", "-", "—", "N/A", "n/a", "none", "NONE":
		return true
	default:
		return false
	}
}
