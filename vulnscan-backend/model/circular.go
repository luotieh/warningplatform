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
	Operator        string                `json:"operator" gorm:"type:varchar(70);comment:操作人ID"`
	OperatorName    string                `json:"operator_name" gorm:"type:varchar(100);comment:操作人名称"`
	OperationTime   time.Time             `json:"operation_time" gorm:"type:timestamp;comment:操作时间"`
	OperationResult string                `json:"operation_result" gorm:"type:varchar(70);comment:操作结果"`
	TargetOrganize  string                `json:"target_organize" gorm:"type:varchar(255);comment:目标组织"`
	Detail          string                `json:"detail" gorm:"type:text;comment:操作详情(JSON)"`
}

func (*CircularOperationLog) TableName() string { return "circular_operation_logs" }

func BuildCircularOperationLog(
	circularId string,
	opType CircularOperationType,
	operatorID, operatorName, result, targetOrganize string,
	detail map[string]interface{},
) CircularOperationLog {
	detailStr := ""
	if detail != nil {
		bs, _ := json.Marshal(detail)
		detailStr = string(bs)
	}
	if operatorName == "" {
		switch operatorID {
		case "system":
			operatorName = "系统"
		case "":
			operatorName = "-"
		default:
			operatorName = operatorID
		}
	}
	now := time.Now()
	return CircularOperationLog{
		ReadOnlyModel: ReadOnlyModel{
			Id:        qulid.GenerateID(),
			CreatedAt: now,
		},
		CircularId:      circularId,
		OperationType:   opType,
		Operator:        operatorID,
		OperatorName:    operatorName,
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
