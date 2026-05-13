package asset

import (
	"encoding/csv"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type assetImportColumn struct {
	Field    string
	Group    string
	Title    string
	Example  string
	Required bool
}

var assetImportColumns = []assetImportColumn{
	{Field: "name", Group: "系统基本信息", Title: "系统名称", Example: "办公自动化系统", Required: true},
	{Field: "organize_name", Group: "系统基本信息", Title: "单位名称", Example: "某某单位", Required: true},
	{Field: "system_type", Group: "系统基本信息", Title: "系统类型", Example: "应用系统", Required: true},
	{Field: "is_online", Group: "系统基本信息", Title: "是否联网", Example: "是", Required: true},
	{Field: "ipv4", Group: "系统基本信息", Title: "IPV4地址", Example: "192.168.1.100", Required: true},
	{Field: "ipv6", Group: "系统基本信息", Title: "IPV6地址", Example: "无", Required: true},
	{Field: "url", Group: "系统基本信息", Title: "网址", Example: "https://oa.example.com", Required: true},
	{Field: "is_key", Group: "系统基本信息", Title: "是否是关键信息基础设施", Example: "否", Required: true},
	{Field: "security_protection_level", Group: "系统基本信息", Title: "安全保护等级", Example: "三级", Required: true},
	{Field: "filing_cert_number", Group: "系统基本信息", Title: "备案证明编号", Example: "CERT-2024-001"},
	{Field: "icp_filing_number", Group: "系统基本信息", Title: "ICP备案号", Example: "京ICP备12345678号"},
	{Field: "public_security_filing", Group: "系统基本信息", Title: "公网安备案号", Example: "京公网安备11010802000000号"},
	{Field: "address", Group: "系统基本信息", Title: "地址", Example: "192.168.1.100"},
	{Field: "type", Group: "系统基本信息", Title: "资产类型", Example: "server"},
	{Field: "data_number", Group: "系统基本信息", Title: "数据编号", Example: "DN-2024-001"},
	{Field: "domain", Group: "系统基本信息", Title: "域名", Example: "oa.example.com"},
	{Field: "port", Group: "系统基本信息", Title: "端口", Example: "443"},
	{Field: "protocol", Group: "系统基本信息", Title: "协议", Example: "https"},
	{Field: "service", Group: "系统基本信息", Title: "服务", Example: "nginx"},
	{Field: "version", Group: "系统基本信息", Title: "版本", Example: "1.24"},
	{Field: "os", Group: "系统基本信息", Title: "操作系统", Example: "Ubuntu 22.04"},
	{Field: "unit_type", Group: "单位基本信息", Title: "单位类型", Example: "事业单位"},
	{Field: "industry_category", Group: "单位基本信息", Title: "行业分类", Example: "政务"},
	{Field: "is_notification_member", Group: "单位基本信息", Title: "通报机制成员单位", Example: "是"},
	{Field: "unified_social_credit_code", Group: "单位基本信息", Title: "统一社会信用代码", Example: "91110000100000000X"},
	{Field: "unit_address", Group: "单位基本信息", Title: "单位地址", Example: "北京市"},
	{Field: "unit_detail_address", Group: "单位基本信息", Title: "单位详细地址", Example: "海淀区xx路1号"},
	{Field: "leader_name", Group: "单位基本信息", Title: "分管领导姓名", Example: "李四"},
	{Field: "leader_title", Group: "单位基本信息", Title: "分管领导职务/职称", Example: "副主任"},
	{Field: "responsible_department_name", Group: "单位基本信息", Title: "责任部门名称", Example: "信息中心"},
	{Field: "department_leader_name", Group: "单位基本信息", Title: "责任部门负责人姓名", Example: "王五"},
	{Field: "department_leader_title", Group: "单位基本信息", Title: "负责人职务/职称", Example: "主任"},
	{Field: "department_leader_phone", Group: "单位基本信息", Title: "负责人电话", Example: "13800000000"},
	{Field: "contact_name", Group: "单位基本信息", Title: "联系人姓名", Example: "赵六"},
	{Field: "contact_title", Group: "单位基本信息", Title: "联系人职务/职称", Example: "工程师"},
	{Field: "contact_phone", Group: "单位基本信息", Title: "联系人电话", Example: "13900000000"},
	{Field: "construction_org", Group: "系统建设单位基本情况", Title: "建设单位名称", Example: "某某建设单位"},
	{Field: "construction_org_location", Group: "系统建设单位基本情况", Title: "所在地", Example: "北京市/海淀区"},
	{Field: "construction_org_address", Group: "系统建设单位基本情况", Title: "详细地址", Example: "海淀区xx路1号"},
	{Field: "construction_org_charge_person", Group: "系统建设单位基本情况", Title: "负责人及职务", Example: "张三/主任"},
	{Field: "construction_org_charge_phone", Group: "系统建设单位基本情况", Title: "联系电话", Example: "13800000000"},
	{Field: "construction_org_security_filing", Group: "系统建设单位基本情况", Title: "公网安备备案号", Example: "京公网安备11010802000000号"},
	{Field: "operation_org", Group: "系统运维单位基本情况", Title: "运维单位名称", Example: "某某运维单位"},
	{Field: "operation_org_location", Group: "系统运维单位基本情况", Title: "所在地", Example: "北京市/海淀区"},
	{Field: "operation_org_address", Group: "系统运维单位基本情况", Title: "详细地址", Example: "海淀区xx路2号"},
	{Field: "operation_org_charge_person", Group: "系统运维单位基本情况", Title: "负责人及职务", Example: "李四/工程师"},
	{Field: "operation_org_charge_phone", Group: "系统运维单位基本情况", Title: "联系电话", Example: "13900000000"},
	{Field: "operation_org_security_filing", Group: "系统运维单位基本情况", Title: "公网安备备案号", Example: "京公网安备11010802000001号"},
	{Field: "data_source", Group: "资产管理信息", Title: "数据来源", Example: "手动导入"},
	{Field: "responsible_user_name", Group: "资产管理信息", Title: "责任人", Example: "张三"},
	{Field: "tags", Group: "资产管理信息", Title: "标签", Example: "核心,互联网"},
	{Field: "remark", Group: "资产管理信息", Title: "备注", Example: "核心业务系统"},
}

var assetExtraImportFields = map[string]bool{
	"unit_type": true, "industry_category": true, "is_notification_member": true,
	"unified_social_credit_code": true, "unit_address": true, "unit_detail_address": true,
	"leader_name": true, "leader_title": true, "responsible_department_name": true,
	"department_leader_name": true, "department_leader_title": true, "department_leader_phone": true,
	"contact_name": true, "contact_title": true, "contact_phone": true,
}

var assetDictImportIDs = map[string]string{
	"type":                      "asset_type",
	"system_type":               "asset_system_type",
	"security_protection_level": "asset_security_level",
	"data_source":               "asset_data_source",
}

func (h *HandlerAsset) ImportAssets(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	var rows [][]string

	switch ext {
	case ".csv":
		rows, err = parseCSV(file)
	case ".xlsx":
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

	headerMap, dataStart := detectAssetImportHeader(rows)
	resolver := h.newAssetImportResolver()
	user, _ := iamsdk.GetCurrentUser(c)

	var items []*model.Asset
	for _, row := range rows[dataStart:] {
		orgID := getCell(row, headerMap, "organize_id")
		if orgID == "" {
			orgID = resolver.resolveOrganizeName(getCell(row, headerMap, "organize_name"))
		}
		item := &model.Asset{
			ID:         qulid.GenerateID(),
			CreatedBy:  user.UserID,
			OrganizeID: firstNonEmpty(orgID, user.OrganizeID),
			Status:     1,
			DataSource: "manual_import",
		}
		item.Name = getCell(row, headerMap, "name")
		item.Address = getCell(row, headerMap, "address")
		if item.Name == "" && item.Address == "" {
			continue
		}
		if item.Name == "" {
			item.Name = item.Address
		}

		item.Type = resolver.resolveDictValue("type", getCell(row, headerMap, "type"))
		if item.Type == "" {
			item.Type = "server"
		}
		item.SystemType = resolver.resolveDictValue("system_type", getCell(row, headerMap, "system_type"))
		item.DataNumber = getCell(row, headerMap, "data_number")
		item.Domain = getCell(row, headerMap, "domain")
		item.IPv4 = getCell(row, headerMap, "ipv4")
		item.IPv6 = getCell(row, headerMap, "ipv6")
		item.URL = getCell(row, headerMap, "url")
		item.Protocol = getCell(row, headerMap, "protocol")
		item.Service = getCell(row, headerMap, "service")
		item.Version = getCell(row, headerMap, "version")
		item.OS = getCell(row, headerMap, "os")
		item.SecurityProtectionLevel = resolver.resolveDictValue("security_protection_level", getCell(row, headerMap, "security_protection_level"))
		item.FilingCertNumber = getCell(row, headerMap, "filing_cert_number")
		item.IcpFilingNumber = getCell(row, headerMap, "icp_filing_number")
		item.PublicSecurityFiling = getCell(row, headerMap, "public_security_filing")
		item.IsOnline = parseBoolDefault(getCell(row, headerMap, "is_online"), true)
		item.IsKey = parseBoolDefault(getCell(row, headerMap, "is_key"), false)
		item.DataSource = model.DataSourceType(firstNonEmpty(resolver.resolveDictValue("data_source", getCell(row, headerMap, "data_source")), "manual_import"))
		item.ConstructionOrgID = resolver.resolveConstructionOrg(buildConstructionOrgImport(row, headerMap, "construction_org"), user.UserID)
		item.OperationOrgID = resolver.resolveConstructionOrg(buildConstructionOrgImport(row, headerMap, "operation_org"), user.UserID)
		item.ResponsibleUserName = getCell(row, headerMap, "responsible_user_name")
		item.Tags = splitTags(getCell(row, headerMap, "tags"))
		item.Extra = buildAssetExtra(row, headerMap)
		item.Remark = getCell(row, headerMap, "remark")
		if port, ok := parseInt(getCell(row, headerMap, "port")); ok {
			item.Port = port
		}

		items = append(items, item)
	}

	if len(items) == 0 {
		web.Fail(c).Msg("无有效数据行").Send()
		return
	}

	count, err := h.svc.BatchImport(items)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(gin.H{"imported": count, "total": len(items)}).Send()
}

func (h *HandlerAsset) DownloadTemplate(c *gin.Context) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	f.SetSheetName(sheet, "资产导入")
	sheet = "资产导入"
	writeGroupedAssetHeader(f, sheet, assetImportColumns)
	for i, col := range assetImportColumns {
		cell, _ := excelize.CoordinatesToCellName(i+1, 3)
		f.SetCellValue(sheet, cell, col.Example)
	}
	_ = f.SetRowHeight(sheet, 1, 24)
	_ = f.SetRowHeight(sheet, 2, 28)
	_ = f.SetColWidth(sheet, "A", lastColumnName(len(assetImportColumns)), 18)
	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      2,
		TopLeftCell: "A3",
		ActivePane:  "bottomLeft",
	})
	addImportDictSheet(f)

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=asset_import_template.xlsx")
	if err := f.Write(c.Writer); err != nil {
		web.Fail(c).Err(err).Send()
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

func detectAssetImportHeader(rows [][]string) (map[string]int, int) {
	if len(rows) >= 2 && looksLikeGroupedAssetHeader(rows[0], rows[1]) {
		return buildGroupedHeaderMap(rows[0], rows[1]), 2
	}
	return buildHeaderMap(rows[0]), 1
}

func looksLikeGroupedAssetHeader(groupRow, fieldRow []string) bool {
	groupCount := 0
	for _, cell := range groupRow {
		switch normalizeHeader(cell) {
		case "系统基本信息", "单位基本信息", "系统建设单位基本情况", "系统运维单位基本情况", "资产管理信息", "导出统计信息":
			groupCount++
		}
	}
	fieldMap := buildGroupedHeaderMap(groupRow, fieldRow)
	_, hasName := fieldMap["name"]
	_, hasAddress := fieldMap["address"]
	return groupCount > 0 && (hasName || hasAddress)
}

func buildGroupedHeaderMap(groupRow, fieldRow []string) map[string]int {
	m := buildHeaderMap(fieldRow)
	groupAliases := map[string]map[string]string{
		"系统建设单位基本情况": {
			"建设单位名称":  "construction_org",
			"单位名称":    "construction_org",
			"名称":      "construction_org",
			"所在地":     "construction_org_location",
			"详细地址":    "construction_org_address",
			"负责人及职务":  "construction_org_charge_person",
			"负责人":     "construction_org_charge_person",
			"联系电话":    "construction_org_charge_phone",
			"公网安备备案号": "construction_org_security_filing",
		},
		"系统运维单位基本情况": {
			"运维单位名称":  "operation_org",
			"单位名称":    "operation_org",
			"名称":      "operation_org",
			"所在地":     "operation_org_location",
			"详细地址":    "operation_org_address",
			"负责人及职务":  "operation_org_charge_person",
			"负责人":     "operation_org_charge_person",
			"联系电话":    "operation_org_charge_phone",
			"公网安备备案号": "operation_org_security_filing",
		},
	}

	currentGroup := ""
	for i, title := range fieldRow {
		if i < len(groupRow) {
			if group := normalizeHeader(groupRow[i]); group != "" {
				currentGroup = group
			}
		}
		fieldTitle := normalizeHeader(title)
		if aliases := groupAliases[currentGroup]; aliases != nil {
			if field, ok := aliases[fieldTitle]; ok {
				m[field] = i
			}
		}
	}
	return m
}

func writeGroupedAssetHeader(f *excelize.File, sheet string, columns []assetImportColumn) {
	groupStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"1F4E78"}, Pattern: 1},
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
	})
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"D9EAF7"}, Pattern: 1},
		Font:      &excelize.Font{Bold: true, Color: "1F2937"},
	})

	groupStart := 1
	for i, col := range columns {
		colIndex := i + 1
		groupCell, _ := excelize.CoordinatesToCellName(colIndex, 1)
		titleCell, _ := excelize.CoordinatesToCellName(colIndex, 2)
		f.SetCellValue(sheet, groupCell, col.Group)
		title := col.Title
		if col.Required {
			title += "(必填)"
		}
		f.SetCellValue(sheet, titleCell, title)
		if i == len(columns)-1 || columns[i+1].Group != col.Group {
			if groupStart != colIndex {
				startCell, _ := excelize.CoordinatesToCellName(groupStart, 1)
				endCell, _ := excelize.CoordinatesToCellName(colIndex, 1)
				_ = f.MergeCell(sheet, startCell, endCell)
			}
			groupStart = colIndex + 1
		}
	}

	lastCol := lastColumnName(len(columns))
	_ = f.SetCellStyle(sheet, "A1", lastCol+"1", groupStyle)
	_ = f.SetCellStyle(sheet, "A2", lastCol+"2", titleStyle)
}

func lastColumnName(count int) string {
	name, _ := excelize.ColumnNumberToName(count)
	return name
}

func buildHeaderMap(headers []string) map[string]int {
	m := make(map[string]int, len(headers))
	nameAliases := map[string]string{
		"资产名称(必填)": "name", "资产名称": "name", "名称": "name", "name": "name", "系统名称": "name", "system_name": "name",
		"地址(必填)": "address", "地址": "address", "address": "address", "ip": "address",
		"资产类型": "type", "type": "type",
		"系统类型": "system_type", "system_type": "system_type",
		"数据编号": "data_number", "data_number": "data_number", "编号": "data_number",
		"域名": "domain", "domain": "domain",
		"ipv4": "ipv4", "ipv6": "ipv6",
		"url": "url", "网址": "url",
		"端口": "port", "port": "port",
		"协议": "protocol", "protocol": "protocol",
		"服务": "service", "service": "service",
		"版本": "version", "version": "version",
		"操作系统": "os", "os": "os",
		"是否联网": "is_online", "is_online": "is_online",
		"关键信息基础设施": "is_key", "是否关键资产": "is_key", "是否是关键信息基础设施": "is_key", "is_key": "is_key",
		"保护等级": "security_protection_level", "安全保护等级": "security_protection_level", "security_protection_level": "security_protection_level", "等保等级": "security_protection_level",
		"等保证号": "filing_cert_number", "备案证明编号": "filing_cert_number", "filing_cert_number": "filing_cert_number",
		"icp备案号": "icp_filing_number", "icp_filing_number": "icp_filing_number", "icp备案": "icp_filing_number",
		"公网安备案号": "public_security_filing", "public_security_filing": "public_security_filing", "公网安备": "public_security_filing",
		"资产所属单位id": "organize_id", "所属单位id": "organize_id", "organize_id": "organize_id",
		"单位名称": "organize_name", "organize_name": "organize_name",
		"建设单位": "construction_org", "建设单位名称": "construction_org", "建设单位id": "construction_org", "construction_org_id": "construction_org", "construction_org": "construction_org",
		"建设单位所在地": "construction_org_location", "construction_org_location": "construction_org_location",
		"建设单位详细地址": "construction_org_address", "construction_org_address": "construction_org_address",
		"建设单位负责人及职务": "construction_org_charge_person", "建设单位负责人": "construction_org_charge_person", "construction_org_charge_person": "construction_org_charge_person",
		"建设单位联系电话": "construction_org_charge_phone", "construction_org_charge_phone": "construction_org_charge_phone",
		"建设单位公网安备备案号": "construction_org_security_filing", "construction_org_security_filing": "construction_org_security_filing",
		"运维单位": "operation_org", "运维单位名称": "operation_org", "运维单位id": "operation_org", "operation_org_id": "operation_org", "operation_org": "operation_org",
		"运维单位所在地": "operation_org_location", "operation_org_location": "operation_org_location",
		"运维单位详细地址": "operation_org_address", "operation_org_address": "operation_org_address",
		"运维单位负责人及职务": "operation_org_charge_person", "运维单位负责人": "operation_org_charge_person", "operation_org_charge_person": "operation_org_charge_person",
		"运维单位联系电话": "operation_org_charge_phone", "operation_org_charge_phone": "operation_org_charge_phone",
		"运维单位公网安备备案号": "operation_org_security_filing", "operation_org_security_filing": "operation_org_security_filing",
		"数据来源": "data_source", "data_source": "data_source",
		"责任人": "responsible_user_name", "responsible_user_name": "responsible_user_name",
		"标签": "tags", "tags": "tags",
		"单位类型": "unit_type", "unit_type": "unit_type",
		"行业分类": "industry_category", "industry_category": "industry_category",
		"通报机制成员单位": "is_notification_member", "is_notification_member": "is_notification_member",
		"统一社会信用代码": "unified_social_credit_code", "unified_social_credit_code": "unified_social_credit_code",
		"单位地址": "unit_address", "unit_address": "unit_address",
		"单位详细地址": "unit_detail_address", "unit_detail_address": "unit_detail_address",
		"分管领导姓名": "leader_name", "leader_name": "leader_name",
		"分管领导职务/职称": "leader_title", "leader_title": "leader_title",
		"责任部门名称": "responsible_department_name", "responsible_department_name": "responsible_department_name",
		"责任部门负责人姓名": "department_leader_name", "department_leader_name": "department_leader_name",
		"负责人职务/职称": "department_leader_title", "department_leader_title": "department_leader_title",
		"负责人电话": "department_leader_phone", "department_leader_phone": "department_leader_phone",
		"联系人姓名": "contact_name", "contact_name": "contact_name",
		"联系人职务/职称": "contact_title", "contact_title": "contact_title",
		"联系人电话": "contact_phone", "contact_phone": "contact_phone",
		"备注": "remark", "remark": "remark",
	}

	for i, h := range headers {
		key := normalizeHeader(h)
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

func normalizeHeader(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "（必填）", "")
	value = strings.ReplaceAll(value, "(必填)", "")
	return value
}

func parseInt(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	return n, err == nil
}

func parseBoolDefault(value string, fallback bool) bool {
	if value == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "是", "启用", "联网":
		return true
	case "0", "false", "no", "n", "否", "停用", "未联网":
		return false
	default:
		return fallback
	}
}

func splitTags(value string) model.StringArray {
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '，' || r == ';' || r == '；' || r == '、'
	})
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			tags = append(tags, part)
		}
	}
	return model.StringArray(tags)
}

func buildAssetExtra(row []string, headerMap map[string]int) model.JSONMap {
	extra := model.JSONMap{}
	for field := range assetExtraImportFields {
		value := getCell(row, headerMap, field)
		if value == "" {
			continue
		}
		if field == "is_notification_member" {
			extra[field] = parseBoolDefault(value, false)
		} else {
			extra[field] = value
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

type constructionOrgImport struct {
	Name           string
	Location       string
	Address        string
	ChargePerson   string
	ChargePhone    string
	SecurityFiling string
}

func buildConstructionOrgImport(row []string, headerMap map[string]int, prefix string) constructionOrgImport {
	return constructionOrgImport{
		Name:           getCell(row, headerMap, prefix),
		Location:       getCell(row, headerMap, prefix+"_location"),
		Address:        getCell(row, headerMap, prefix+"_address"),
		ChargePerson:   getCell(row, headerMap, prefix+"_charge_person"),
		ChargePhone:    getCell(row, headerMap, prefix+"_charge_phone"),
		SecurityFiling: getCell(row, headerMap, prefix+"_security_filing"),
	}
}

type assetImportResolver struct {
	db             *gorm.DB
	dictMaps       map[string]map[string]string
	orgByName      map[string]string
	orgByID        map[string]model.ConstructionOrg
	organizeByName map[string]string
}

func (h *HandlerAsset) newAssetImportResolver() *assetImportResolver {
	resolver := &assetImportResolver{
		dictMaps:       map[string]map[string]string{},
		orgByName:      map[string]string{},
		orgByID:        map[string]model.ConstructionOrg{},
		organizeByName: map[string]string{},
	}
	if svc, ok := h.svc.(*serviceAsset); ok {
		resolver.db = svc.session()
	}
	if resolver.db == nil {
		return resolver
	}
	for field, dictID := range assetDictImportIDs {
		items := []model.SystemDictItem{}
		_ = resolver.db.Where("dict_id = ? AND enabled = ?", dictID, true).Find(&items).Error
		m := map[string]string{}
		for _, item := range items {
			m[item.Value] = item.Value
			m[item.Label] = item.Value
		}
		resolver.dictMaps[field] = m
	}
	var orgs []model.ConstructionOrg
	_ = resolver.db.Find(&orgs).Error
	for _, org := range orgs {
		resolver.orgByName[org.ID] = org.ID
		resolver.orgByName[org.Name] = org.ID
		resolver.orgByID[org.ID] = org
	}
	var organizes []model.Organize
	_ = resolver.db.Select("id, name").Find(&organizes).Error
	for _, o := range organizes {
		resolver.organizeByName[o.Name] = o.ID
	}
	return resolver
}

func (r *assetImportResolver) resolveOrganizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if id, ok := r.organizeByName[name]; ok {
		return id
	}
	return ""
}

func (r *assetImportResolver) resolveDictValue(field string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if m := r.dictMaps[field]; m != nil {
		if resolved, ok := m[value]; ok {
			return resolved
		}
	}
	return value
}

func (r *assetImportResolver) resolveConstructionOrg(input constructionOrgImport, createdBy string) string {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return ""
	}
	if id, ok := r.orgByName[input.Name]; ok {
		r.updateConstructionOrgDetails(id, input)
		return id
	}
	if r.db == nil {
		return input.Name
	}
	org := model.ConstructionOrg{
		ID:             qulid.GenerateID(),
		Name:           input.Name,
		Location:       input.Location,
		Address:        input.Address,
		ChargePerson:   input.ChargePerson,
		ChargePhone:    input.ChargePhone,
		SecurityFiling: input.SecurityFiling,
		CreatedBy:      createdBy,
	}
	if err := r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&org).Error; err != nil {
		return input.Name
	}
	r.orgByName[input.Name] = org.ID
	r.orgByName[org.ID] = org.ID
	r.orgByID[org.ID] = org
	return org.ID
}

func (r *assetImportResolver) updateConstructionOrgDetails(id string, input constructionOrgImport) {
	if r.db == nil {
		return
	}
	updates := map[string]any{}
	if input.Location != "" {
		updates["location"] = input.Location
	}
	if input.Address != "" {
		updates["address"] = input.Address
	}
	if input.ChargePerson != "" {
		updates["charge_person"] = input.ChargePerson
	}
	if input.ChargePhone != "" {
		updates["charge_phone"] = input.ChargePhone
	}
	if input.SecurityFiling != "" {
		updates["security_filing"] = input.SecurityFiling
	}
	if len(updates) == 0 {
		return
	}
	_ = r.db.Model(&model.ConstructionOrg{}).Where("id = ?", id).Updates(updates).Error
}

func addImportDictSheet(f *excelize.File) {
	sheet := "填写说明"
	_, _ = f.NewSheet(sheet)
	rows := [][]string{
		{"字段", "说明"},
		{"资产类型 / 系统类型 / 安全保护等级 / 数据来源", "可填写系统管理-数据字典中的标签或值，例如“应用系统”或 application。"},
		{"建设单位 / 运维单位", "可填写已有建设运维单位名称或ID；填写新名称时导入会自动创建基础单位记录。"},
		{"资产所属单位ID", "来源于 IAM 组织，请填写组织ID；留空时使用当前用户所属组织。"},
		{"布尔字段", "支持 是/否、true/false、1/0。"},
		{"标签", "多个标签用逗号、分号或顿号分隔。"},
		{"所在地", "建设运维单位的所在地建议先在资产管理-建设运维单位页面维护。"},
	}
	for r, row := range rows {
		for c, value := range row {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+1)
			f.SetCellValue(sheet, cell, value)
		}
	}
	_ = f.SetColWidth(sheet, "A", "A", 28)
	_ = f.SetColWidth(sheet, "B", "B", 96)
}
