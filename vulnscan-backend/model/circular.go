package model

import (
	"encoding/json"
	"time"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

// ─── 通报主表 ───

type Circular struct {
	FullModel
	Code                      string             `json:"code" gorm:"type:varchar(70);not null;comment:通报编号"`
	Title                     string             `json:"title" gorm:"type:varchar(255);not null;comment:通报标题"`
	CustomCode                string             `json:"custom_code" gorm:"type:varchar(70);comment:自定义标识"`
	Source                    CircularDataSource `json:"source" gorm:"type:varchar(70);comment:通报来源"`
	Organize                  string             `json:"organize" gorm:"type:varchar(255);not null;comment:产生通报的单位"`
	DisposalOrganize          string             `json:"disposal_organize" gorm:"type:varchar(255);comment:处置单位"`
	DistributionTime          string             `json:"distribution_time" gorm:"type:varchar(70);comment:派发时间"`
	ProcessingDeadline        string             `json:"processing_deadline" gorm:"type:varchar(70);comment:处理期限"`
	CircularTemplate          string             `json:"circular_template" gorm:"type:varchar(70);not null;comment:通报表单模板标识"`
	CircularData              JSONMapSlice       `json:"circular_data" gorm:"type:text;comment:录入表单模板提交数据"`
	DisposalTemplate          string             `json:"disposal_template" gorm:"type:varchar(70);comment:处置表单唯一标识"`
	DisposalData              JSONMapSlice       `json:"disposal_data" gorm:"type:text;comment:处置表单提交数据"`
	DisposalTemplateHistoryId string             `json:"disposal_template_history_id" gorm:"type:varchar(70);comment:派发时处置模板的历史版本ID"`
	Status                    CircularStatus     `json:"status" gorm:"type:varchar(70);not null;comment:通报状态"`
}

func (*Circular) TableName() string { return "circulars" }

// ─── 通报在不同组织的状态 ───

type CircularOrganizeStatus struct {
	AutoIncModel
	CircularId     string         `json:"circular_id" gorm:"type:varchar(70);index;comment:关联通报ID"`
	DistributionId string         `json:"distribution_id" gorm:"type:varchar(70);comment:关联派发记录ID"`
	Organize       string         `json:"organize" gorm:"type:varchar(255);index;comment:组织"`
	Status         CircularStatus `json:"status" gorm:"type:varchar(70);comment:状态"`
}

func (*CircularOrganizeStatus) TableName() string { return "circular_organize_status" }

// ─── 通报派发记录 ───

type CircularDistribution struct {
	FullModel
	CircularId           string `json:"circular_id" gorm:"type:varchar(70);index;comment:关联通报标识"`
	CurrentOrganize      string `json:"current_organize" gorm:"type:varchar(255);comment:派发发起组织"`
	TargetOrganize       string `json:"target_organize" gorm:"type:varchar(255);comment:派发目标组织"`
	ProcessingDeadline   string `json:"processing_deadline" gorm:"type:varchar(70);comment:处理期限"`
	Requirements         string `json:"requirements" gorm:"type:varchar(700);comment:处理要求"`
	Depth                int    `json:"depth" gorm:"default:0;comment:派发深度(0=首次派发)"`
	ParentDistributionId string `json:"parent_distribution_id" gorm:"type:varchar(70);comment:父级派发记录ID"`
	DisposalData         string `json:"disposal_data" gorm:"type:text;comment:派发时处置模板的TemplateData快照"`
}

func (*CircularDistribution) TableName() string { return "circular_distributions" }

// ─── 派发闭包表（树形层级结构） ───

type CircularDistributionClosure struct {
	Ancestor   string `json:"ancestor" gorm:"type:varchar(80);not null;index:idx_cdc_ancestor_descendant,unique,priority:1;index:idx_cdc_ancestor;comment:祖先节点"`
	Descendant string `json:"descendant" gorm:"type:varchar(80);not null;index:idx_cdc_ancestor_descendant,unique,priority:2;index:idx_cdc_descendant;comment:后代节点"`
	Distance   int    `json:"distance" gorm:"not null;default:0;comment:距离"`
}

func (*CircularDistributionClosure) TableName() string { return "circular_distribution_closures" }

// ─── 处置记录 ───

type CircularDisposal struct {
	FullModel
	Circular         string `json:"circular" gorm:"type:varchar(70);comment:关联通报"`
	CurrentOrganize  string `json:"current_organize" gorm:"type:varchar(255);comment:处置组织"`
	TargetOrganize   string `json:"target_organize" gorm:"type:varchar(255);comment:审核组织"`
	DisposalResult   string `json:"disposal_result" gorm:"type:text;comment:处置结果"`
	DisposalTime     string `json:"disposal_time" gorm:"type:varchar(70);comment:处置时间"`
	DisposalQuestion string `json:"disposal_question" gorm:"type:varchar(70);comment:处置问题"`
}

func (*CircularDisposal) TableName() string { return "circular_disposals" }

// ─── 通报表单模板 ───

type CircularTemplate struct {
	FullModel
	TemplateName          string               `json:"template_name" gorm:"type:varchar(70);comment:模板名称"`
	TemplateDescription   string               `json:"template_description" gorm:"type:varchar(70);comment:模板描述"`
	TemplateData          string               `json:"template_data" gorm:"type:text;comment:模板数据"`
	TemplateHistoryLastId string               `json:"template_history_last_id,omitempty" gorm:"type:varchar(70);comment:模板历史最新ID"`
	Type                  CircularTemplateType `json:"type" gorm:"type:varchar(70);comment:模板类型"`
	DefaultFlag           bool                 `json:"default_flag" gorm:"default:false;comment:是否默认模板"`
}

func (*CircularTemplate) TableName() string { return "circular_templates" }

// ─── 模板历史版本 ───

type CircularTemplateHistory struct {
	FullModel
	TemplateId   string               `json:"template" gorm:"type:varchar(70);comment:关联模板ID"`
	TemplateName string               `json:"template_name" gorm:"type:varchar(70);comment:模板名称"`
	Type         CircularTemplateType `json:"type" gorm:"type:varchar(70);comment:模板类型"`
	TemplateData string               `json:"template_data" gorm:"type:text;comment:模板数据"`
}

func (*CircularTemplateHistory) TableName() string { return "circular_template_history" }

// ─── 审核记录 ───

type CircularReview struct {
	FullModel
	CircularId     string `json:"circular_id" gorm:"type:varchar(70);index;comment:关联通报"`
	DistributionId string `json:"distribution_id" gorm:"type:varchar(70);comment:关联派发记录"`
	Organize       string `json:"organize" gorm:"type:varchar(255);comment:审核组织"`
	Depth          int    `json:"depth" gorm:"default:0;comment:审核层级深度"`
	Review         string `json:"review" gorm:"type:varchar(70);comment:审核状态"`
	Instructions   string `json:"instructions" gorm:"type:text;comment:审核说明"`
	Annex          string `json:"annex" gorm:"type:varchar(70);comment:附件"`
}

func (*CircularReview) TableName() string { return "circular_reviews" }

// ─── 操作日志 ───

type CircularOperationLog struct {
	ReadOnlyModel
	CircularId      string                `json:"circular_id" gorm:"type:varchar(70);index;comment:关联通报标识"`
	OperationType   CircularOperationType `json:"operation_type" gorm:"type:varchar(70);index;comment:操作类型"`
	Operator        string                `json:"operator" gorm:"type:varchar(70);comment:操作人"`
	OperationTime   time.Time             `json:"operation_time" gorm:"type:timestamp;comment:操作时间"`
	OperationResult string                `json:"operation_result" gorm:"type:varchar(70);comment:操作结果"`
	TargetOrganize  string                `json:"target_organize" gorm:"type:varchar(255);comment:目标组织"`
	Detail          string                `json:"detail" gorm:"type:text;comment:操作详情(JSON)"`
}

func (*CircularOperationLog) TableName() string { return "circular_operation_logs" }

func BuildCircularOperationLog(circularId string, opType CircularOperationType, operator string, result string, targetOrganize string, detail map[string]interface{}) CircularOperationLog {
	detailStr := ""
	if detail != nil {
		bs, _ := json.Marshal(detail)
		detailStr = string(bs)
	}
	now := time.Now()
	return CircularOperationLog{
		ReadOnlyModel: ReadOnlyModel{
			Id:        qulid.GenerateID(),
			CreatedAt: now,
		},
		CircularId:      circularId,
		OperationType:   opType,
		Operator:        operator,
		OperationTime:   now,
		OperationResult: result,
		TargetOrganize:  targetOrganize,
		Detail:          detailStr,
	}
}

func CreateCircularOperationLog(session *gorm.DB, log CircularOperationLog) error {
	return session.Create(&log).Error
}

// ─── 安全事件流转记录 ───

type CircularTransferRecord struct {
	FullModel
	CircularId   string `json:"circular_id" gorm:"type:varchar(70);index;comment:关联通报ID"`
	IncidentNo   string `json:"incident_no" gorm:"type:varchar(100);uniqueIndex;comment:安全事件编号"`
	SourceSystem string `json:"source_system" gorm:"type:varchar(100);comment:来源系统标识"`
	TransferTime string `json:"transfer_time" gorm:"type:varchar(70);comment:流转时间"`
	SourceData   string `json:"source_data" gorm:"type:text;comment:原始数据(JSON)"`
}

func (*CircularTransferRecord) TableName() string { return "circular_transfer_records" }

// ─── 旧版通报关联模型（导入导出用） ───

type CircularInputNotice struct {
	Id             int64                  `json:"-" gorm:"primaryKey;autoIncrement"`
	Code           string                 `json:"code" gorm:"type:varchar(70);index"`
	InvolvedAssets CircularInvolvedAssets `json:"involved_assets" gorm:"foreignKey:NoticeCode;references:Code"`
	HazardInfo     CircularHazardInfo     `json:"hazard_info" gorm:"foreignKey:NoticeCode;references:Code"`
	CreateAt       int64                  `json:"create_at,omitempty" gorm:"autoCreateTime"`
	UpdateAt       int64                  `json:"update_at,omitempty" gorm:"autoUpdateTime"`
	CreateBy       string                 `json:"create_by,omitempty" gorm:"type:varchar(70)"`
	UpdateBy       string                 `json:"update_by,omitempty" gorm:"type:varchar(70)"`
}

type CircularInvolvedAssets struct {
	Id                     int64                 `json:"-" gorm:"primaryKey;autoIncrement"`
	Code                   string                `json:"code" gorm:"type:varchar(70);index"`
	NoticeCode             string                `json:"notice_code" gorm:"type:varchar(100)"`
	SystemName             string                `json:"system_name" gorm:"type:varchar(255)"`
	WebsiteDomain          string                `json:"website_domain" gorm:"type:varchar(70)"`
	WebsiteIP              string                `json:"website_ip" gorm:"type:varchar(50)"`
	PlaceOrigin            string                `json:"place_origin" gorm:"type:varchar(70)"`
	AffiliatedUnit         string                `json:"affiliated_unit" gorm:"type:varchar(255)"`
	UnitType               string                `json:"unit_type" gorm:"type:varchar(70)"`
	Industry               string                `json:"industry" gorm:"type:varchar(70)"`
	RegisterNumber         string                `json:"register_number" gorm:"type:varchar(100)"`
	SecurityLevel          CircularSecurityLevel `json:"security_level" gorm:"type:varchar(70)"`
	SecurityRegisterNumber string                `json:"security_register_number" gorm:"type:varchar(100)"`
	CreateAt               int64                 `json:"create_at,omitempty" gorm:"autoCreateTime"`
	UpdateAt               int64                 `json:"update_at,omitempty" gorm:"autoUpdateTime"`
}

type CircularHazardInfo struct {
	Id                   int64                `json:"-" gorm:"primaryKey;autoIncrement"`
	Code                 string               `json:"code" gorm:"type:varchar(70);index"`
	NoticeCode           string               `json:"notice_code" gorm:"type:varchar(100)"`
	HazardNumber         string               `json:"hazard_number" gorm:"type:varchar(100)"`
	DataNumber           string               `json:"data_number" gorm:"type:varchar(100)"`
	HazardName           string               `json:"hazard_name" gorm:"type:varchar(255)"`
	HazardType           string               `json:"hazard_type" gorm:"type:varchar(70)"`
	WarningLevel         CircularWarningLevel `json:"warning_level" gorm:"type:varchar(70)"`
	HazardLevel          CircularHazardLevel  `json:"hazard_level" gorm:"type:varchar(70)"`
	HazardURL            string               `json:"hazard_url" gorm:"type:varchar(50)"`
	DiscoveryTime        string               `json:"discovery_time" gorm:"type:varchar(70)"`
	ManufacturerLocation string               `json:"manufacturer_location" gorm:"type:varchar(255)"`
	ReportingVendor      string               `json:"reporting_vendor" gorm:"type:varchar(100)"`
	VendorReportTime     string               `json:"vendor_report_time" gorm:"type:varchar(70)"`
	InvolveInfoAmount    string               `json:"involve_info_amount" gorm:"type:varchar(50)"`
	InvolveInfoType      string               `json:"involve_info_type" gorm:"type:varchar(50)"`
	HazardDescription    string               `json:"hazard_description" gorm:"type:text"`
	CreateAt             int64                `json:"create_at,omitempty" gorm:"autoCreateTime"`
	UpdateAt             int64                `json:"update_at,omitempty" gorm:"autoUpdateTime"`
}
