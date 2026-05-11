package asset

import (
	"encoding/csv"
	"fmt"
	"strings"

	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

type HandlerAsset struct {
	svc assetContract.ServiceAsset
}

func NewHandlerAsset(svc assetContract.ServiceAsset) *HandlerAsset {
	return &HandlerAsset{svc: svc}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (h *HandlerAsset) List(c *gin.Context) {
	var query assetContract.AssetQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerAsset) GetByID(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	item, err := h.svc.GetByID(id)
	if err != nil {
		web.Resp(c, web.NotFound)
		return
	}

	web.RespContent(c, web.Success, item)
}

func (h *HandlerAsset) Create(c *gin.Context) {
	var req assetContract.CreateAssetReq
	if !web.ValidationJson(c, &req) {
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	item := model.Asset{
		ID:         qulid.GenerateID(),
		Name:       req.Name,
		Type:       req.Type,
		Address:    req.Address,
		GroupID:    req.GroupID,
		Port:       req.Port,
		Tags:       req.Tags,
		Status:     1,
		CreatedBy:  user.UserID,
		OrganizeID: firstNonEmpty(req.OrganizeID, user.OrganizeID),

		Domain:                  req.Domain,
		IPv4:                    req.IPv4,
		IPv6:                    req.IPv6,
		URL:                     req.URL,
		Protocol:                req.Protocol,
		Service:                 req.Service,
		Version:                 req.Version,
		OS:                      req.OS,
		DataNumber:              req.DataNumber,
		SystemName:              req.SystemName,
		SystemType:              req.SystemType,
		IsOnline:                req.IsOnline,
		IsKey:                   req.IsKey,
		SecurityProtectionLevel: req.SecurityProtectionLevel,
		FilingCertNumber:        req.FilingCertNumber,
		IcpFilingNumber:         req.IcpFilingNumber,
		ConstructionOrgID:       req.ConstructionOrgID,
		OperationOrgID:          req.OperationOrgID,
		DataSource:              model.DataSourceType(req.DataSource),
		ResponsibleUserID:       req.ResponsibleUserID,
		ResponsibleUserName:     req.ResponsibleUserName,
		Extra:                   req.Extra,
		Remark:                  req.Remark,
		LifecycleState:          "discovered",
	}

	if err := h.svc.Create(&item); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, item)
}

type updateAssetReq struct {
	Name       *string  `json:"name"`
	Type       *string  `json:"type"`
	Address    *string  `json:"address"`
	GroupID    *string  `json:"group_id"`
	OrganizeID *string  `json:"organize_id"`
	Port       *int     `json:"port"`
	Tags       []string `json:"tags"`
	Status     *int     `json:"status"`

	Domain                  *string        `json:"domain"`
	IPv4                    *string        `json:"ipv4"`
	IPv6                    *string        `json:"ipv6"`
	URL                     *string        `json:"url"`
	Protocol                *string        `json:"protocol"`
	Service                 *string        `json:"service"`
	Version                 *string        `json:"version"`
	OS                      *string        `json:"os"`
	DataNumber              *string        `json:"data_number"`
	SystemName              *string        `json:"system_name"`
	SystemType              *string        `json:"system_type"`
	IsOnline                *bool          `json:"is_online"`
	IsKey                   *bool          `json:"is_key"`
	SecurityProtectionLevel *string        `json:"security_protection_level"`
	FilingCertNumber        *string        `json:"filing_cert_number"`
	IcpFilingNumber         *string        `json:"icp_filing_number"`
	ConstructionOrgID       *string        `json:"construction_org_id"`
	OperationOrgID          *string        `json:"operation_org_id"`
	DataSource              *string        `json:"data_source"`
	ResponsibleUserID       *string        `json:"responsible_user_id"`
	ResponsibleUserName     *string        `json:"responsible_user_name"`
	Extra                   *model.JSONMap `json:"extra"`
	Remark                  *string        `json:"remark"`
}

func (h *HandlerAsset) Update(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	var req updateAssetReq
	if !web.ValidationJson(c, &req) {
		return
	}

	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Type != nil {
		updates["type"] = *req.Type
	}
	if req.Address != nil {
		updates["address"] = *req.Address
	}
	if req.GroupID != nil {
		updates["group_id"] = *req.GroupID
	}
	if req.OrganizeID != nil {
		updates["organize_id"] = *req.OrganizeID
	}
	if req.Port != nil {
		updates["port"] = *req.Port
	}
	if req.Tags != nil {
		updates["tags"] = model.StringArray(req.Tags)
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.Domain != nil {
		updates["domain"] = *req.Domain
	}
	if req.IPv4 != nil {
		updates["ipv4"] = *req.IPv4
	}
	if req.IPv6 != nil {
		updates["ipv6"] = *req.IPv6
	}
	if req.URL != nil {
		updates["url"] = *req.URL
	}
	if req.Protocol != nil {
		updates["protocol"] = *req.Protocol
	}
	if req.Service != nil {
		updates["service"] = *req.Service
	}
	if req.Version != nil {
		updates["version"] = *req.Version
	}
	if req.OS != nil {
		updates["os"] = *req.OS
	}
	if req.DataNumber != nil {
		updates["data_number"] = *req.DataNumber
	}
	if req.SystemName != nil {
		updates["system_name"] = *req.SystemName
	}
	if req.SystemType != nil {
		updates["system_type"] = *req.SystemType
	}
	if req.IsOnline != nil {
		updates["is_online"] = *req.IsOnline
	}
	if req.IsKey != nil {
		updates["is_key"] = *req.IsKey
	}
	if req.SecurityProtectionLevel != nil {
		updates["security_protection_level"] = *req.SecurityProtectionLevel
	}
	if req.FilingCertNumber != nil {
		updates["filing_cert_number"] = *req.FilingCertNumber
	}
	if req.IcpFilingNumber != nil {
		updates["icp_filing_number"] = *req.IcpFilingNumber
	}
	if req.ConstructionOrgID != nil {
		updates["construction_org_id"] = *req.ConstructionOrgID
	}
	if req.OperationOrgID != nil {
		updates["operation_org_id"] = *req.OperationOrgID
	}
	if req.DataSource != nil {
		updates["data_source"] = *req.DataSource
	}
	if req.ResponsibleUserID != nil {
		updates["responsible_user_id"] = *req.ResponsibleUserID
	}
	if req.ResponsibleUserName != nil {
		updates["responsible_user_name"] = *req.ResponsibleUserName
	}
	if req.Extra != nil {
		updates["extra"] = *req.Extra
	}
	if req.Remark != nil {
		updates["remark"] = *req.Remark
	}

	if len(updates) == 0 {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	updates["updated_by"] = user.UserID

	if err := h.svc.Update(id, updates); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerAsset) Delete(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	if err := h.svc.Delete(id); err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.Resp(c, web.Success)
}

func (h *HandlerAsset) BatchUpdate(c *gin.Context) {
	var req assetContract.BatchUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}

	allowedFields := map[string]bool{
		"group_id": true, "organize_id": true, "status": true, "system_type": true,
		"security_protection_level": true, "lifecycle_state": true,
		"data_source": true, "responsible_user_name": true,
		"responsible_user_id": true, "is_key": true, "is_online": true,
		"construction_org_id": true, "operation_org_id": true, "remark": true,
	}
	sanitized := make(map[string]any)
	for k, v := range req.Updates {
		if allowedFields[k] {
			sanitized[k] = v
		}
	}
	if len(sanitized) == 0 {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	affected, err := h.svc.BatchUpdate(req.IDs, sanitized)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	web.RespContent(c, web.Success, gin.H{"affected": affected})
}

func (h *HandlerAsset) Export(c *gin.Context) {
	var query assetContract.AssetQuery
	_ = c.ShouldBindQuery(&query)
	query.Page = 1
	query.PageSize = 10000

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, _, err := h.svc.List(query, scope)
	if err != nil {
		web.Resp(c, web.InternalError)
		return
	}

	format := c.DefaultQuery("format", "csv")
	if format == "csv" {
		h.exportCSV(c, items)
	} else if format == "xlsx" {
		h.exportXLSX(c, items)
	} else {
		web.Resp(c, web.ParamsMissingRequired)
	}
}

func (h *HandlerAsset) exportCSV(c *gin.Context, items []model.Asset) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=assets.csv")

	_, _ = c.Writer.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	columns := assetExportColumns()
	header := make([]string, 0, len(columns))
	for _, col := range columns {
		header = append(header, col.Title)
	}
	_ = writer.Write(header)
	orgMap := h.constructionOrgMap(items)
	for _, a := range items {
		_ = writer.Write(assetExportRow(a, columns, orgMap))
	}
}

func (h *HandlerAsset) exportXLSX(c *gin.Context, items []model.Asset) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	f.SetSheetName(sheet, "资产台账")
	sheet = "资产台账"

	columns := assetExportColumns()
	writeGroupedAssetHeader(f, sheet, columns)
	orgMap := h.constructionOrgMap(items)
	for r, item := range items {
		row := assetExportRow(item, columns, orgMap)
		for cidx, value := range row {
			cell, _ := excelize.CoordinatesToCellName(cidx+1, r+3)
			f.SetCellValue(sheet, cell, value)
		}
	}
	_ = f.SetRowHeight(sheet, 1, 24)
	_ = f.SetRowHeight(sheet, 2, 28)
	_ = f.SetColWidth(sheet, "A", lastColumnName(len(columns)), 18)
	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		YSplit:      2,
		TopLeftCell: "A3",
		ActivePane:  "bottomLeft",
	})

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=assets.xlsx")
	if err := f.Write(c.Writer); err != nil {
		web.Resp(c, web.InternalError)
	}
}

func assetExportColumns() []assetImportColumn {
	columns := make([]assetImportColumn, 0, len(assetImportColumns)+4)
	columns = append(columns, assetImportColumns...)
	columns = append(columns,
		assetImportColumn{Field: "risk_score", Group: "导出统计信息", Title: "风险分"},
		assetImportColumn{Field: "vuln_count", Group: "导出统计信息", Title: "漏洞数"},
		assetImportColumn{Field: "status", Group: "导出统计信息", Title: "状态"},
		assetImportColumn{Field: "created_at", Group: "导出统计信息", Title: "创建时间"},
	)
	return columns
}

func assetExportRow(asset model.Asset, columns []assetImportColumn, orgMap map[string]model.ConstructionOrg) []string {
	row := make([]string, 0, len(columns))
	for _, col := range columns {
		row = append(row, assetExportValue(asset, col.Field, orgMap))
	}
	return row
}

func assetExportValue(asset model.Asset, field string, orgMap map[string]model.ConstructionOrg) string {
	switch field {
	case "name":
		return asset.Name
	case "address":
		return asset.Address
	case "type":
		return asset.Type
	case "system_name":
		return asset.SystemName
	case "system_type":
		return asset.SystemType
	case "data_number":
		return asset.DataNumber
	case "domain":
		return asset.Domain
	case "ipv4":
		return asset.IPv4
	case "ipv6":
		return asset.IPv6
	case "url":
		return asset.URL
	case "port":
		if asset.Port > 0 {
			return fmt.Sprintf("%d", asset.Port)
		}
		return ""
	case "protocol":
		return asset.Protocol
	case "service":
		return asset.Service
	case "version":
		return asset.Version
	case "os":
		return asset.OS
	case "is_online":
		return formatBool(asset.IsOnline)
	case "is_key":
		return formatBool(asset.IsKey)
	case "security_protection_level":
		return asset.SecurityProtectionLevel
	case "filing_cert_number":
		return asset.FilingCertNumber
	case "icp_filing_number":
		return asset.IcpFilingNumber
	case "organize_id":
		return asset.OrganizeID
	case "construction_org":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "name")
	case "construction_org_location":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "location")
	case "construction_org_address":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "address")
	case "construction_org_charge_person":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "charge_person")
	case "construction_org_charge_phone":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "charge_phone")
	case "construction_org_security_filing":
		return constructionOrgExportValue(orgMap, asset.ConstructionOrgID, "security_filing")
	case "operation_org":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "name")
	case "operation_org_location":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "location")
	case "operation_org_address":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "address")
	case "operation_org_charge_person":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "charge_person")
	case "operation_org_charge_phone":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "charge_phone")
	case "operation_org_security_filing":
		return constructionOrgExportValue(orgMap, asset.OperationOrgID, "security_filing")
	case "data_source":
		return string(asset.DataSource)
	case "lifecycle_state":
		return string(asset.LifecycleState)
	case "responsible_user_name":
		return asset.ResponsibleUserName
	case "tags":
		return strings.Join(asset.Tags, ",")
	case "remark":
		return asset.Remark
	case "risk_score":
		return fmt.Sprintf("%.1f", asset.RiskScore)
	case "vuln_count":
		return fmt.Sprintf("%d", asset.VulnCount)
	case "status":
		return fmt.Sprintf("%d", asset.Status)
	case "created_at":
		return asset.CreatedAt.Format("2006-01-02 15:04:05")
	default:
		if assetExtraImportFields[field] {
			return extraValue(asset.Extra, field)
		}
		return ""
	}
}

func constructionOrgExportValue(orgMap map[string]model.ConstructionOrg, id string, field string) string {
	if id == "" {
		return ""
	}
	org, ok := orgMap[id]
	if !ok {
		if field == "name" {
			return id
		}
		return ""
	}
	switch field {
	case "name":
		return firstNonEmpty(org.Name, id)
	case "location":
		return org.Location
	case "address":
		return org.Address
	case "charge_person":
		return org.ChargePerson
	case "charge_phone":
		return org.ChargePhone
	case "security_filing":
		return org.SecurityFiling
	default:
		return ""
	}
}

func formatBool(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func extraValue(extra model.JSONMap, key string) string {
	if extra == nil {
		return ""
	}
	value, ok := extra[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case bool:
		return formatBool(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (h *HandlerAsset) constructionOrgMap(items []model.Asset) map[string]model.ConstructionOrg {
	ids := make([]string, 0)
	seen := map[string]bool{}
	for _, item := range items {
		for _, id := range []string{item.ConstructionOrgID, item.OperationOrgID} {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	result := map[string]model.ConstructionOrg{}
	if len(ids) == 0 {
		return result
	}
	svc, ok := h.svc.(*serviceAsset)
	if !ok {
		return result
	}
	var orgs []model.ConstructionOrg
	_ = svc.session().Where("id IN ?", ids).Find(&orgs).Error
	for _, org := range orgs {
		result[org.ID] = org
	}
	return result
}
