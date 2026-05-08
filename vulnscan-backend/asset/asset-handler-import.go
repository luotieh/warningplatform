package asset

import (
	"encoding/csv"
	"io"
	"path/filepath"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

var importHeaders = []string{
	"name", "address", "type", "system_name", "system_type", "data_number",
	"domain", "ipv4", "url", "port", "protocol", "security_protection_level",
	"filing_cert_number", "icp_filing_number", "responsible_user_name", "remark",
}

func (h *HandlerAsset) ImportAssets(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	var rows [][]string

	switch ext {
	case ".csv":
		rows, err = parseCSV(file)
	case ".xlsx", ".xls":
		rows, err = parseExcel(file)
	default:
		web.Fail(c).Msg("仅支持 .csv / .xlsx 格式").Send()
		return
	}
	if err != nil {
		web.Fail(c).Msg("文件解析失败: " + err.Error()).Send()
		return
	}

	if len(rows) < 2 {
		web.Fail(c).Msg("文件为空或仅有表头").Send()
		return
	}

	headerMap := buildHeaderMap(rows[0])
	user, _ := iamsdk.GetCurrentUser(c)

	var items []*model.Asset
	for _, row := range rows[1:] {
		item := &model.Asset{
			ID:             qulid.GenerateID(),
			CreatedBy:      user.UserID,
			OrganizeID:     user.OrganizeID,
			Status:         1,
			DataSource:     "manual_import",
			LifecycleState: "discovered",
		}
		item.Name = getCell(row, headerMap, "name")
		item.Address = getCell(row, headerMap, "address")
		if item.Name == "" && item.Address == "" {
			continue
		}
		if item.Name == "" {
			item.Name = item.Address
		}

		item.Type = getCell(row, headerMap, "type")
		if item.Type == "" {
			item.Type = "server"
		}
		item.SystemName = getCell(row, headerMap, "system_name")
		item.SystemType = getCell(row, headerMap, "system_type")
		item.DataNumber = getCell(row, headerMap, "data_number")
		item.Domain = getCell(row, headerMap, "domain")
		item.IPv4 = getCell(row, headerMap, "ipv4")
		item.URL = getCell(row, headerMap, "url")
		item.Protocol = getCell(row, headerMap, "protocol")
		item.SecurityProtectionLevel = getCell(row, headerMap, "security_protection_level")
		item.FilingCertNumber = getCell(row, headerMap, "filing_cert_number")
		item.IcpFilingNumber = getCell(row, headerMap, "icp_filing_number")
		item.ResponsibleUserName = getCell(row, headerMap, "responsible_user_name")
		item.Remark = getCell(row, headerMap, "remark")

		items = append(items, item)
	}

	if len(items) == 0 {
		web.Fail(c).Msg("无有效数据行").Send()
		return
	}

	count, err := h.svc.BatchImport(items)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, gin.H{"imported": count, "total": len(items)})
}

func (h *HandlerAsset) DownloadTemplate(c *gin.Context) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	headers := []string{
		"资产名称(必填)", "地址(必填)", "资产类型", "系统名称", "系统类型",
		"数据编号", "域名", "IPv4", "URL", "端口", "协议",
		"保护等级", "等保证号", "ICP备案号", "责任人", "备注",
	}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}
	example := []string{
		"OA系统", "192.168.1.100", "server", "办公自动化系统", "application",
		"DN-2024-001", "oa.example.com", "192.168.1.100", "https://oa.example.com", "443", "https",
		"level3", "CERT-2024-001", "京ICP备12345678号", "张三", "核心业务系统",
	}
	for i, v := range example {
		cell, _ := excelize.CoordinatesToCellName(i+1, 2)
		f.SetCellValue(sheet, cell, v)
	}

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=asset_import_template.xlsx")
	if err := f.Write(c.Writer); err != nil {
		web.Resp(c, web.InternalError)
	}
}

func parseCSV(r io.Reader) ([][]string, error) {
	reader := csv.NewReader(r)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	return reader.ReadAll()
}

func parseExcel(r io.Reader) ([][]string, error) {
	f, err := excelize.OpenReader(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sheet := f.GetSheetName(0)
	return f.GetRows(sheet)
}

func buildHeaderMap(headers []string) map[string]int {
	m := make(map[string]int, len(headers))
	nameAliases := map[string]string{
		"资产名称(必填)": "name", "资产名称": "name", "名称": "name", "name": "name",
		"地址(必填)": "address", "地址": "address", "address": "address", "ip": "address",
		"资产类型": "type", "type": "type",
		"系统名称": "system_name", "system_name": "system_name",
		"系统类型": "system_type", "system_type": "system_type",
		"数据编号": "data_number", "data_number": "data_number", "编号": "data_number",
		"域名": "domain", "domain": "domain",
		"ipv4": "ipv4",
		"url":  "url",
		"端口":   "port", "port": "port",
		"协议": "protocol", "protocol": "protocol",
		"保护等级": "security_protection_level", "security_protection_level": "security_protection_level", "等保等级": "security_protection_level",
		"等保证号": "filing_cert_number", "filing_cert_number": "filing_cert_number",
		"icp备案号": "icp_filing_number", "icp_filing_number": "icp_filing_number", "icp备案": "icp_filing_number",
		"责任人": "responsible_user_name", "responsible_user_name": "responsible_user_name",
		"备注": "remark", "remark": "remark",
	}

	for i, h := range headers {
		key := strings.TrimSpace(strings.ToLower(h))
		if field, ok := nameAliases[key]; ok {
			m[field] = i
		}
	}
	return m
}

func getCell(row []string, headerMap map[string]int, field string) string {
	if idx, ok := headerMap[field]; ok && idx < len(row) {
		return strings.TrimSpace(row[idx])
	}
	return ""
}
