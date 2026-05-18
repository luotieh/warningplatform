package asset

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/organize"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/identity"
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

var assetLedgerColumns = []assetImportColumn{
	{Field: "name", Group: "系统基本信息", Title: "系统名称", Example: "办公自动化系统", Required: true},
	{Field: "organize_name", Group: "系统基本信息", Title: "单位名称", Example: "某某单位", Required: true},
	{Field: "asset_family", Group: "系统基本信息", Title: "资产分类", Example: "IP资产", Required: true},
	{Field: "is_online", Group: "系统基本信息", Title: "是否联网", Example: "是", Required: true},
	{Field: "ipv4", Group: "系统基本信息", Title: "IPV4地址", Example: "192.168.1.100", Required: false},
	{Field: "ipv6", Group: "系统基本信息", Title: "IPV6地址", Example: "无", Required: true},
	{Field: "address", Group: "系统基本信息", Title: "访问地址", Example: "https://oa.example.com", Required: true},
	{Field: "is_key", Group: "系统基本信息", Title: "是否是关键信息基础设施", Example: "否", Required: true},
	{Field: "security_protection_level", Group: "系统基本信息", Title: "安全保护等级", Example: "无", Required: true},
	{Field: "filing_cert_number", Group: "系统基本信息", Title: "等保备案证明编号", Example: "CERT-2024-001"},
	{Field: "icp_filing_number", Group: "系统基本信息", Title: "ICP备案号", Example: "京ICP备12345678号"},
	{Field: "public_security_filing", Group: "系统基本信息", Title: "公网安备案号", Example: "京公网安备11010802000000号"},
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
	{Field: "unit_location_code", Group: "单位基本信息", Title: "单位省市区", Example: "江苏省/徐州市/云龙区"},
	{Field: "unit_address", Group: "单位基本信息", Title: "详细地址", Example: "xx路1号"},
	{Field: "leader_name", Group: "单位基本信息", Title: "网络安全分管领导", Example: "李四"},
	{Field: "leader_title", Group: "单位基本信息", Title: "分管领导职务/职称", Example: "副主任"},
	{Field: "responsible_department_name", Group: "单位基本信息", Title: "网络安全责任部门", Example: "信息中心"},
	{Field: "department_leader_name", Group: "单位基本信息", Title: "责任部门负责人姓名", Example: "王五"},
	{Field: "department_leader_title", Group: "单位基本信息", Title: "负责人职务/职称", Example: "主任"},
	{Field: "department_leader_phone", Group: "单位基本信息", Title: "负责人电话", Example: "13800000000"},
	{Field: "contact_name", Group: "单位基本信息", Title: "联系人姓名", Example: "赵六"},
	{Field: "contact_title", Group: "单位基本信息", Title: "联系人职务/职称", Example: "工程师"},
	{Field: "contact_phone", Group: "单位基本信息", Title: "联系人电话", Example: "13900000000"},
	{Field: "operation_org", Group: "系统运维单位基本情况", Title: "运维单位名称", Example: "某某运维单位"},
	{Field: "operation_org_location", Group: "系统运维单位基本情况", Title: "所在地", Example: "北京市/海淀区"},
	{Field: "operation_org_address", Group: "系统运维单位基本情况", Title: "详细地址", Example: "海淀区xx路2号"},
	{Field: "operation_org_charge_person", Group: "系统运维单位基本情况", Title: "负责人及职务", Example: "李四/工程师"},
	{Field: "operation_org_charge_phone", Group: "系统运维单位基本情况", Title: "联系电话", Example: "13900000000"},
	{Field: "operation_org_security_filing", Group: "系统运维单位基本情况", Title: "公网安备备案号", Example: "京公网安备11010802000001号"},
	{Field: "unified_social_credit_code", Group: "单位补充信息", Title: "统一社会信用代码", Example: "91110000100000000X"},
	{Field: "parent_organize_name", Group: "单位补充信息", Title: "上级单位名称", Example: "某某上级单位"},
}

var assetImportFields = []string{
	"name",
	"organize_name",
	"asset_family",
	"is_online",
	"ipv4",
	"ipv6",
	"address",
	"is_key",
	"security_protection_level",
	"filing_cert_number",
	"icp_filing_number",
	"public_security_filing",
	"domain",
	"operation_org",
	"unified_social_credit_code",
	"parent_organize_name",
}

var assetImportColumns = pickAssetColumns(assetLedgerColumnsVisible(), assetImportFields)

func pickAssetColumns(columns []assetImportColumn, fields []string) []assetImportColumn {
	fieldMap := make(map[string]assetImportColumn, len(columns))
	for _, col := range columns {
		fieldMap[col.Field] = col
	}

	result := make([]assetImportColumn, 0, len(fields))
	for _, field := range fields {
		if col, ok := fieldMap[field]; ok {
			result = append(result, col)
		}
	}
	return result
}

// assetOrganizeImportFields 导入时写入所属单位档案，不进入资产 extra。
var assetOrganizeImportFields = map[string]bool{
	"unit_type": true, "industry_category": true, "is_notification_member": true,
	"unified_social_credit_code": true, "unit_address": true, "unit_location_code": true,
	"leader_name": true, "leader_title": true, "responsible_department_name": true,
	"department_leader_name": true, "department_leader_title": true, "department_leader_phone": true,
	"contact_name": true, "contact_title": true, "contact_phone": true,
}

var assetDictImportIDs = map[string]string{
	"asset_family":              "asset_family",
	"security_protection_level": "asset_security_level",
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
	user, userOK := iamsdk.GetCurrentUser(c)
	createdBy := ""
	defaultParentID := ""
	if userOK {
		createdBy = user.UserID
		defaultParentID = resolveImportDefaultParentID(user.OrganizeID)
	}
	resolver := h.newAssetImportResolver(createdBy, defaultParentID)

	var items []*model.Asset
	for rowIdx, row := range rows[dataStart:] {
		orgID := strings.TrimSpace(getCell(row, headerMap, "organize_id"))
		if orgID == "" {
			orgName := strings.TrimSpace(getCell(row, headerMap, "organize_name"))
			if orgName == "" {
				web.Fail(c).Msg(fmt.Sprintf("第 %d 行：请填写单位名称或所属单位 ID", dataStart+rowIdx+1)).Send()
				return
			}
			orgID, err = resolver.resolveOrCreateOrganize(c.Request.Context(), orgName)
			if err != nil {
				web.Fail(c).Msg(formatImportRowError(dataStart+rowIdx+1, err)).Send()
				return
			}
			if orgID == "" {
				web.Fail(c).Msg(fmt.Sprintf("第 %d 行：无法创建或匹配单位「%s」", dataStart+rowIdx+1, orgName)).Send()
				return
			}
		}
		item := &model.Asset{
			ID:         qulid.GenerateID(),
			CreatedBy:  createdBy,
			OrganizeID: firstNonEmpty(orgID, defaultParentID),
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

		item.AssetFamily = resolver.resolveDictValue("asset_family", getCell(row, headerMap, "asset_family"))
		if item.AssetFamily == "" {
			item.AssetFamily = "ip"
		}
		item.DataNumber = getCell(row, headerMap, "data_number")
		item.Domain = getCell(row, headerMap, "domain")
		item.IPv4 = getCell(row, headerMap, "ipv4")
		item.IPv6 = getCell(row, headerMap, "ipv6")
		item.Protocol = getCell(row, headerMap, "protocol")
		item.Service = getCell(row, headerMap, "service")
		item.Version = getCell(row, headerMap, "version")
		item.OS = getCell(row, headerMap, "os")
		securityLevel := strings.TrimSpace(getCell(row, headerMap, "security_protection_level"))
		if securityLevel == "无" {
			item.SecurityProtectionLevel = ""
		} else {
			item.SecurityProtectionLevel = resolver.resolveDictValue("security_protection_level", securityLevel)
		}
		item.FilingCertNumber = getCell(row, headerMap, "filing_cert_number")
		item.IcpFilingNumber = getCell(row, headerMap, "icp_filing_number")
		item.PublicSecurityFiling = getCell(row, headerMap, "public_security_filing")
		item.IsOnline = parseBoolDefault(getCell(row, headerMap, "is_online"), true)
		item.IsKey = parseBoolDefault(getCell(row, headerMap, "is_key"), false)
		constructionInput := buildConstructionOrgImport(row, headerMap, "construction_org")
		if constructionOrgImportHasData(constructionInput) {
			if err := validateConstructionOrgImport(constructionInput); err != nil {
				web.Fail(c).Msg(fmt.Sprintf("第 %d 行：%s", dataStart+rowIdx+1, err.Error())).Send()
				return
			}
			item.ConstructionOrgID = resolver.resolveConstructionOrg(constructionInput, createdBy)
		}
		opInput := buildConstructionOrgImport(row, headerMap, "operation_org")
		if constructionOrgImportHasData(opInput) {
			if err := validateConstructionOrgImport(opInput); err != nil {
				web.Fail(c).Msg(fmt.Sprintf("第 %d 行：%s", dataStart+rowIdx+1, err.Error())).Send()
				return
			}
			item.OperationOrgID = resolver.resolveConstructionOrg(opInput, createdBy)
		}
		item.ResponsibleUserName = getCell(row, headerMap, "responsible_user_name")
		item.Tags = splitTags(getCell(row, headerMap, "tags"))
		item.Extra = nil
		item.Remark = getCell(row, headerMap, "remark")
		if item.OrganizeID != "" {
			if orgUpdates := buildOrganizeUpdatesFromImportRow(row, headerMap); orgUpdates != nil {
				organize.NormalizeOrganizeUpdates(orgUpdates)
				if err := organize.ValidateOrganizeProfileUpdates(orgUpdates); err != nil {
					web.Fail(c).Msg(formatImportRowError(dataStart+rowIdx+1, err)).Send()
					return
				}
			}
			if err := resolver.syncOrganizeProfileFromImportRow(c.Request.Context(), item.OrganizeID, row, headerMap); err != nil {
				web.Fail(c).Msg(formatImportRowError(dataStart+rowIdx+1, err)).Send()
				return
			}
		}
		if port, ok := parseInt(getCell(row, headerMap, "port")); ok {
			item.Port = port
		}
		if err := validateAssetImportRow(dataStart+rowIdx+1, item.IPv4, item.Port); err != nil {
			web.Fail(c).Msg(err.Error()).Send()
			return
		}
		normalizeAssetAddressFields(item)

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

	var sess *gorm.DB
	if svc, ok := h.svc.(*serviceAsset); ok {
		sess = svc.session()
	}
	choices := h.buildAssetImportTemplateChoices(sess)
	dictRanges, err := writeAssetImportDictOptionsSheet(f, choices)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if err := applyAssetImportDropdownValidations(f, sheet, assetImportColumns, choices, dictRanges); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

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
		case "系统基本信息", "单位基本信息", "系统运维单位基本情况", "单位补充信息", "导出统计信息":
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
		"等保证号": "filing_cert_number", "等保备案证明编号": "filing_cert_number",
		"备案证明编号": "filing_cert_number", "filing_cert_number": "filing_cert_number",
		"单位省市区": "unit_location_code", "unit_location_code": "unit_location_code",
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
		"上级单位名称": "parent_organize_name", "上级单位": "parent_organize_name", "parent_organize_name": "parent_organize_name",
		"单位地址": "unit_address", "unit_address": "unit_address",
		"单位详细地址": "unit_address", "unit_detail_address": "unit_address",
		"分管领导姓名": "leader_name", "网络安全分管领导": "leader_name", "leader_name": "leader_name",
		"分管领导职务/职称": "leader_title", "leader_title": "leader_title",
		"责任部门名称": "responsible_department_name", "网络安全责任部门": "responsible_department_name", "responsible_department_name": "responsible_department_name",
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

func (r *assetImportResolver) syncOrganizeProfileFromImportRow(ctx context.Context, orgID string, row []string, headerMap map[string]int) error {
	updates := buildOrganizeUpdatesFromImportRow(row, headerMap)
	parentName := strings.TrimSpace(getCell(row, headerMap, "parent_organize_name"))
	if parentName != "" {
		parentID, err := r.lookupOrganizeByName(ctx, parentName)
		if err != nil {
			return err
		}
		if parentID == "" {
			return fmt.Errorf("未找到上级单位「%s」，请先在组织管理中创建或填写正确名称", parentName)
		}
		if parentID == orgID {
			return fmt.Errorf("上级单位不能与当前单位相同")
		}
		updates["parent_id"] = parentID
	}
	if len(updates) == 0 {
		return nil
	}
	organize.NormalizeOrganizeUpdates(updates)
	if err := organize.ValidateOrganizeProfileUpdates(updates); err != nil {
		return err
	}
	if credit, ok := updates["unified_social_credit_code"].(string); ok && strings.TrimSpace(credit) != "" {
		credit = strings.TrimSpace(credit)
		var conflict model.Organize
		if err := r.db.Where("unified_social_credit_code = ? AND id <> ? AND deleted_at IS NULL", credit, orgID).
			First(&conflict).Error; err == nil {
			return fmt.Errorf("统一社会信用代码「%s」已被单位「%s」使用", credit, conflict.Name)
		}
	}
	if err := r.db.Model(&model.Organize{}).Where("id = ? AND deleted_at IS NULL", orgID).Updates(updates).Error; err != nil {
		return importDBError("更新单位档案", err)
	}
	return nil
}

// lookupOrganizeByName 仅按名称匹配已有单位（不自动新建），用于解析上级单位。
func (r *assetImportResolver) lookupOrganizeByName(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if id, ok := r.organizeByName[name]; ok && id != "" {
		return id, nil
	}
	info, err := r.findIAMOrganizeByName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("查询上级单位失败: %w", err)
	}
	if info == nil {
		return "", nil
	}
	if id := r.ensureLocalOrganize(info); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("同步上级单位「%s」到本地失败", name)
}

func buildOrganizeUpdatesFromImportRow(row []string, headerMap map[string]int) map[string]interface{} {
	updates := map[string]interface{}{}
	for field := range assetOrganizeImportFields {
		value := getCell(row, headerMap, field)
		if value == "" {
			continue
		}
		if field == "is_notification_member" {
			updates[field] = parseBoolDefault(value, false)
			continue
		}
		if field == "unit_location_code" {
			continue
		}
		if field == "unit_address" {
			updates["address"] = value
			updates["unit_detail_address"] = ""
			continue
		}
		updates[field] = value
	}
	if loc := getCell(row, headerMap, "unit_location_code"); loc != "" {
		if addr, ok := updates["address"].(string); ok && addr != "" {
			updates["address"] = strings.TrimSpace(loc + " " + addr)
		} else {
			updates["address"] = loc
		}
		updates["unit_detail_address"] = ""
	}
	if len(updates) == 0 {
		return nil
	}
	return updates
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

func constructionOrgImportHasData(input constructionOrgImport) bool {
	return strings.TrimSpace(input.Name) != "" ||
		strings.TrimSpace(input.Location) != "" ||
		strings.TrimSpace(input.Address) != "" ||
		strings.TrimSpace(input.ChargePerson) != "" ||
		strings.TrimSpace(input.ChargePhone) != "" ||
		strings.TrimSpace(input.SecurityFiling) != ""
}

type assetImportResolver struct {
	db              *gorm.DB
	dictMaps        map[string]map[string]string
	orgByName       map[string]string
	orgByID         map[string]model.ConstructionOrg
	organizeByName  map[string]string
	iam             *iamsdk.Client
	iamOrganizes    []*identity.OrganizeInfo
	iamOrganizesErr error
	iamOrganizesGot bool
	createdBy       string
	defaultParentID string
}

func (h *HandlerAsset) newAssetImportResolver(createdBy string, defaultParentID string) *assetImportResolver {
	resolver := &assetImportResolver{
		dictMaps:        map[string]map[string]string{},
		orgByName:       map[string]string{},
		orgByID:         map[string]model.ConstructionOrg{},
		organizeByName:  map[string]string{},
		iam:             h.iam,
		createdBy:       createdBy,
		defaultParentID: defaultParentID,
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

// resolveOrCreateOrganize 按名称匹配已有单位；不存在时尝试 IAM，仍无则本地新建（仅需单位名称，可选上级为导入人所属单位）。
func (r *assetImportResolver) resolveOrCreateOrganize(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if id, ok := r.organizeByName[name]; ok && id != "" {
		return id, nil
	}

	if id, err := r.findLocalOrganizeByName(name); err != nil {
		return "", err
	} else if id != "" {
		r.organizeByName[name] = id
		return id, nil
	}

	if info, err := r.findIAMOrganizeByName(ctx, name); err != nil {
		return "", fmt.Errorf("查询 IAM 单位「%s」失败: %w", name, err)
	} else if info != nil {
		id, err := r.ensureLocalOrganizeOrError(info)
		if err != nil {
			return "", err
		}
		r.organizeByName[name] = id
		return id, nil
	}

	if info, err := r.createIAMOrganize(ctx, name); err != nil {
		slog.Warn("import: IAM 创建单位失败，将尝试仅本地新建", "name", name, "error", err)
	} else if info != nil {
		id, err := r.ensureLocalOrganizeOrError(info)
		if err != nil {
			return "", err
		}
		r.organizeByName[name] = id
		return id, nil
	}

	return r.createLocalOrganizeByName(name)
}

func (r *assetImportResolver) findLocalOrganizeByName(name string) (string, error) {
	if r.db == nil {
		return "", nil
	}
	var items []model.Organize
	if err := r.db.Where("name = ? AND deleted_at IS NULL", name).
		Order("created_at ASC").Limit(2).Find(&items).Error; err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", nil
	}
	if len(items) > 1 {
		slog.Warn("import: 本地存在多个同名单位，使用最早创建的一条", "name", name)
	}
	return items[0].ID, nil
}

func (r *assetImportResolver) ensureLocalOrganizeOrError(info *identity.OrganizeInfo) (string, error) {
	if info == nil {
		return "", fmt.Errorf("单位信息为空")
	}
	if id := r.ensureLocalOrganize(info); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("同步单位「%s」到本地失败", strings.TrimSpace(info.Name))
}

func (r *assetImportResolver) createLocalOrganizeByName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if id, ok := r.organizeByName[name]; ok {
		return id, nil
	}
	if r.db == nil {
		return "", fmt.Errorf("无法创建单位「%s」：数据库不可用", name)
	}

	org := model.Organize{
		ID:        qulid.GenerateID(),
		Name:      name,
		ParentID:  strings.TrimSpace(r.defaultParentID),
		CreatedBy: r.createdBy,
	}
	// 仅写入必要列，避免 GORM 将信用代码零值 '' 写入库触发 UNIQUE（多条空串冲突）。
	if err := r.db.Select("ID", "Name", "ParentID", "CreatedBy").Create(&org).Error; err != nil {
		return "", importOrganizeCreateError(name, err)
	}
	r.organizeByName[name] = org.ID
	return org.ID, nil
}

func (r *assetImportResolver) findIAMOrganizeByName(ctx context.Context, name string) (*identity.OrganizeInfo, error) {
	if r.iam == nil || strings.TrimSpace(name) == "" {
		return nil, nil
	}
	name = strings.TrimSpace(name)
	if !r.iamOrganizesGot {
		r.iamOrganizesGot = true
		r.iamOrganizes, r.iamOrganizesErr = organize.ListAllIAMOrganizes(ctx, r.iam.Organize)
	}
	if r.iamOrganizesErr != nil {
		return organize.FindIAMOrganizeByExactName(ctx, r.iam.Organize, name)
	}
	for _, info := range r.iamOrganizes {
		if info != nil && strings.TrimSpace(info.Name) == name {
			return info, nil
		}
	}
	return nil, nil
}

func (r *assetImportResolver) createIAMOrganize(ctx context.Context, name string) (*identity.OrganizeInfo, error) {
	if r.iam == nil || name == "" {
		return nil, nil
	}
	// 创建前再查一次，防止并发导入或缓存未命中时重复写入 IAM。
	if existing, err := r.findIAMOrganizeByName(ctx, name); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	info, err := r.iam.Organize.CreateOrganize(ctx, &identity.CreateOrganizeRequest{
		Name:     name,
		ParentID: r.defaultParentID,
	})
	if err != nil {
		return nil, err
	}
	if r.iamOrganizesGot && info != nil {
		r.iamOrganizes = append(r.iamOrganizes, info)
	}
	return info, nil
}

func (r *assetImportResolver) ensureLocalOrganize(info *identity.OrganizeInfo) string {
	if info == nil {
		return ""
	}
	if id, ok := r.organizeByName[info.Name]; ok && id != "" {
		return id
	}
	if r.db == nil {
		return info.ID
	}
	org := model.Organize{
		ID:        info.ID,
		Name:      info.Name,
		ParentID:  info.ParentID,
		CreatedBy: r.createdBy,
	}
	credit := strings.TrimSpace(info.CreditCode)
	if credit != "" {
		org.UnifiedSocialCreditCode = credit
	}
	db := r.db
	onConflictCols := []string{"name", "parent_id"}
	if credit == "" {
		db = db.Omit("unified_social_credit_code")
	} else {
		onConflictCols = append(onConflictCols, "unified_social_credit_code")
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onConflictCols),
	}).Create(&org).Error; err != nil {
		return ""
	}
	r.organizeByName[info.Name] = info.ID
	return info.ID
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
		{"资产分类 / 安全保护等级", "下拉选项实时来自「系统管理 → 数据字典」中 asset_family、asset_security_level 的已启用项；详见「字典选项」工作表。安全保护等级另含「无」表示未分级。"},
		{"是否联网", "资产登记必填项，与列表「在线状态」（实时探测）无关。固定下拉：是、否。"},
		{"是否关键基础设施", "固定下拉：是、否。"},
		{"建设单位 / 运维单位", "可填写已有建设运维单位名称或ID；填写新名称时导入会自动创建基础单位记录。"},
		{"资产所属单位ID", "来源于 IAM 组织，请填写组织ID；留空时使用当前用户所属组织。"},
		{"单位名称", "必填（未填所属单位 ID 时）。优先匹配已有单位；不存在时自动新建单位（仅需名称）。新建单位的默认上级为当前登录账号所属单位；也可在「上级单位名称」列指定其它上级。"},
		{"单位补充信息", "位于模板末尾。统一社会信用代码、上级单位名称均为可选；信用代码写入单位档案；上级单位须已存在（按名称匹配，不自动新建）。"},
		{"单位基本信息", "完整台账导出含单位类型、行业、地址、联系人等；精简导入模板不含这些列，可在组织管理或后续编辑补全。"},
		{"布尔字段", "支持 是/否、true/false、1/0。"},
		{"标签", "多个标签用逗号、分号或顿号分隔。"},
		{"探测补齐字段", "端口、协议、服务、版本、操作系统等字段默认不在模板中，建议通过后续探测自动补齐。"},
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

func resolveImportDefaultParentID(organizeID string) string {
	return strings.TrimSpace(organizeID)
}
