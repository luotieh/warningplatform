package asset

import (
	"fmt"
	"strings"

	assetContract "vulnscan-backend/asset/asset-contract"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerAsset struct {
	svc assetContract.ServiceAsset
}

func NewHandlerAsset(svc assetContract.ServiceAsset) *HandlerAsset {
	return &HandlerAsset{svc: svc}
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
		OrganizeID: user.OrganizeID,

		Domain:                  req.Domain,
		IPv4:                    req.IPv4,
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
	Name    *string  `json:"name"`
	Type    *string  `json:"type"`
	Address *string  `json:"address"`
	GroupID *string  `json:"group_id"`
	Port    *int     `json:"port"`
	Tags    []string `json:"tags"`
	Status  *int     `json:"status"`

	Domain                  *string `json:"domain"`
	IPv4                    *string `json:"ipv4"`
	URL                     *string `json:"url"`
	Protocol                *string `json:"protocol"`
	Service                 *string `json:"service"`
	Version                 *string `json:"version"`
	OS                      *string `json:"os"`
	DataNumber              *string `json:"data_number"`
	SystemName              *string `json:"system_name"`
	SystemType              *string `json:"system_type"`
	IsOnline                *bool   `json:"is_online"`
	IsKey                   *bool   `json:"is_key"`
	SecurityProtectionLevel *string `json:"security_protection_level"`
	FilingCertNumber        *string `json:"filing_cert_number"`
	IcpFilingNumber         *string `json:"icp_filing_number"`
	ConstructionOrgID       *string `json:"construction_org_id"`
	OperationOrgID          *string `json:"operation_org_id"`
	DataSource              *string `json:"data_source"`
	ResponsibleUserID       *string `json:"responsible_user_id"`
	ResponsibleUserName     *string `json:"responsible_user_name"`
	Remark                  *string `json:"remark"`
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
		"group_id": true, "status": true, "system_type": true,
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
	} else {
		web.Resp(c, web.ParamsMissingRequired)
	}
}

func (h *HandlerAsset) exportCSV(c *gin.Context, items []model.Asset) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=assets.csv")

	bom := "\xEF\xBB\xBF"
	header := "ID,名称,系统名称,地址,域名,IPv4,端口,类型,系统类型,保护等级,生命周期,风险分,责任人,数据来源,创建时间\n"
	c.Writer.WriteString(bom + header)

	for _, a := range items {
		port := ""
		if a.Port > 0 {
			port = fmt.Sprintf("%d", a.Port)
		}
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.1f,%s,%s,%s\n",
			csvEscape(a.ID), csvEscape(a.Name), csvEscape(a.SystemName),
			csvEscape(a.Address), csvEscape(a.Domain), csvEscape(a.IPv4), port,
			csvEscape(a.Type), csvEscape(a.SystemType),
			csvEscape(a.SecurityProtectionLevel), csvEscape(string(a.LifecycleState)),
			a.RiskScore, csvEscape(a.ResponsibleUserName), csvEscape(string(a.DataSource)),
			a.CreatedAt.Format("2006-01-02 15:04:05"))
		c.Writer.WriteString(line)
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
