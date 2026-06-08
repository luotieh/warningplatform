package model

import (
	"encoding/json"
	"time"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

// ─── 安全事件主表 ───

type SecurityIncident struct {
	FullModel
	IncidentNo        string         `gorm:"uniqueIndex;type:varchar(100);not null" json:"incident_no"`
	Name              string         `gorm:"type:varchar(255);not null" json:"name"`
	Level             int            `gorm:"default:1;comment:事件等级" json:"level"`
	Source            int            `gorm:"default:1;comment:数据来源" json:"source"`
	Status            int            `gorm:"default:1;comment:事件状态" json:"status"`
	OrganizeID        string         `gorm:"type:varchar(64);index;comment:所属组织" json:"organize_id"`
	ReportTime        time.Time      `gorm:"type:timestamp;comment:上报时间" json:"report_time"`
	AiPreStatus       int            `gorm:"default:0;comment:AI预审状态" json:"ai_pre_status"`
	AiOpinion         string         `gorm:"type:text;comment:AI预审意见" json:"ai_opinion"`
	AiConfidence      float64        `gorm:"comment:AI置信度" json:"ai_confidence"`
	RiskScore         float64        `gorm:"default:0;comment:AI风险评分(0-100)" json:"risk_score"`
	AiTags            string         `gorm:"type:varchar(500);comment:AI标签(逗号分隔)" json:"ai_tags"`
	AiCategory        string         `gorm:"type:varchar(100);comment:AI分类" json:"ai_category"`
	AiVulnDesc        string         `gorm:"type:text;comment:AI漏洞描述" json:"ai_vuln_desc"`
	AiVulnHarm        string         `gorm:"type:text;comment:AI漏洞危害" json:"ai_vuln_harm"`
	AiFixAdvice       string         `gorm:"type:text;comment:AI修复建议" json:"ai_fix_advice"`
	RemediationResult string         `gorm:"type:text;comment:整改结果" json:"remediation_result"`
	AssetDetailID     string         `gorm:"type:varchar(80);comment:关联资产表ID" json:"asset_detail_id"`
	EventMetadataID   string         `gorm:"type:varchar(80);comment:关联元数据表ID" json:"event_metadata_id"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"deleted_at"`

	RemediationPlan     string     `gorm:"type:text;comment:整改方案" json:"remediation_plan"`
	RemediationDeadline *time.Time `gorm:"type:timestamp;comment:整改截止日期" json:"remediation_deadline"`
	RemediationAssignee string     `gorm:"type:varchar(255);comment:整改责任人" json:"remediation_assignee"`
	RemediationSubmitAt *time.Time `gorm:"type:timestamp;comment:整改提交时间" json:"remediation_submit_at"`
	VerifiedAt          *time.Time `gorm:"type:timestamp;comment:验证通过时间" json:"verified_at"`
	CloseReason         string     `gorm:"type:text;comment:关闭原因" json:"close_reason"`
	ClosedAt            *time.Time `gorm:"type:timestamp;comment:关闭时间" json:"closed_at"`

	SLALevel         int        `gorm:"default:0;comment:SLA等级" json:"sla_level"`
	SLADeadline      *time.Time `gorm:"type:timestamp;comment:SLA响应截止时间" json:"sla_deadline"`
	SLAStatus        int        `gorm:"default:0;comment:SLA状态" json:"sla_status"`
	SLAEscalatedAt   *time.Time `gorm:"type:timestamp;comment:SLA升级时间" json:"sla_escalated_at"`
	SLAEscalatedTo   string     `gorm:"type:varchar(255);comment:SLA升级通知对象" json:"sla_escalated_to"`
	SLAReminderCount int        `gorm:"default:0;comment:SLA催办次数" json:"sla_reminder_count"`
	SLALastReminder  *time.Time `gorm:"type:timestamp;comment:上次催办时间" json:"sla_last_reminder"`

	AssetDetail   *IncidentAsset    `gorm:"foreignKey:AssetDetailID" json:"asset_detail,omitempty"`
	EventMetadata *IncidentMetadata `gorm:"foreignKey:EventMetadataID" json:"event_metadata,omitempty"`
}

func (SecurityIncident) TableName() string { return "security_incidents" }

// ─── 涉事资产详情 ───

type IncidentAsset struct {
	FullModel
	AssetName    string `gorm:"type:varchar(255);comment:资产名称" json:"asset_name"`
	SystemName   string `gorm:"type:varchar(255);comment:系统名称" json:"system_name"`
	DomainIP     string `gorm:"type:varchar(255);comment:网站域名/IP" json:"domain_ip"`
	SiteIP       string `gorm:"type:varchar(100);comment:网站IP" json:"site_ip"`
	Unit         string `gorm:"type:varchar(255);comment:隶属单位" json:"unit"`
	UnitType     string `gorm:"type:varchar(100);comment:单位类型" json:"unit_type"`
	Industry     string `gorm:"type:varchar(100);comment:所属行业" json:"industry"`
	MLPSRecordNo string `gorm:"type:varchar(100);comment:等保备案号" json:"mlps_record_no"`
	MLPSLevel    string `gorm:"type:varchar(50);comment:等保等级" json:"mlps_level"`
	MIITRecordNo string `gorm:"type:varchar(100);comment:工信部备案号" json:"miit_record_no"`
	Region       string `gorm:"type:varchar(100);comment:归属地" json:"region"`
}

func (IncidentAsset) TableName() string { return "incident_assets" }

// ─── 事件元数据（含漏洞详情） ───

type IncidentMetadata struct {
	FullModel
	DataNo              string    `gorm:"type:varchar(100);comment:数据编号" json:"data_no"`
	IncidentType        string    `gorm:"type:varchar(100);comment:事件类型" json:"incident_type"`
	IncidentURL         string    `gorm:"type:varchar(500);comment:隐患URL" json:"incident_url"`
	DiscoveryTime       time.Time `gorm:"type:timestamp;comment:发现时间" json:"discovery_time"`
	VendorRegion        string    `gorm:"type:varchar(100);comment:厂商上报归属地" json:"vendor_region"`
	VendorName          string    `gorm:"type:varchar(255);comment:上报厂商" json:"vendor_name"`
	IncidentDescription string    `gorm:"type:text;comment:事件描述" json:"incident_description"`
	VendorTime          time.Time `gorm:"type:timestamp;comment:厂商上报时间" json:"vendor_time"`
	AffectedCount       string    `gorm:"type:varchar(100);comment:涉及信息数量" json:"affected_count"`
	AffectedType        string    `gorm:"type:varchar(100);comment:涉及信息类型" json:"affected_type"`

	CvssScore         float64 `gorm:"type:decimal(3,1);default:0;comment:CVSS评分(0-10)" json:"cvss_score"`
	CveId             string  `gorm:"type:varchar(50);comment:CVE编号" json:"cve_id"`
	OwaspCategory     string  `gorm:"type:varchar(100);comment:OWASP分类" json:"owasp_category"`
	ExploitDifficulty string  `gorm:"type:varchar(50);comment:利用难度" json:"exploit_difficulty"`
	AffectScope       string  `gorm:"type:text;comment:影响范围描述" json:"affect_scope"`
}

func (IncidentMetadata) TableName() string { return "incident_metadata" }

// ─── 事件操作日志 ───

type IncidentOperationLog struct {
	ReadOnlyModel
	IncidentId    string    `json:"incident_id" gorm:"type:varchar(80);index;comment:关联事件ID"`
	IncidentNo    string    `json:"incident_no" gorm:"type:varchar(100);index;comment:隐患编号"`
	OperationType string    `json:"operation_type" gorm:"type:varchar(50);index;comment:操作类型"`
	OperatorId    string    `json:"operator_id" gorm:"type:varchar(80);comment:操作人ID"`
	OperatorName  string    `json:"operator_name" gorm:"type:varchar(100);comment:操作人名称"`
	OperationTime time.Time `json:"operation_time" gorm:"type:timestamp;comment:操作时间"`
	Result        string    `json:"result" gorm:"type:varchar(50);comment:操作结果"`
	Detail        string    `json:"detail" gorm:"type:text;comment:操作详情JSON"`
	SourceSystem  string    `json:"source_system" gorm:"type:varchar(50);comment:来源系统"`
}

func (*IncidentOperationLog) TableName() string { return "incident_operation_logs" }

func BuildIncidentOperationLog(
	incidentId, incidentNo, opType, operatorId, operatorName, result string,
	detail map[string]interface{},
	sourceSystem string,
) IncidentOperationLog {
	detailStr := ""
	if detail != nil {
		bs, _ := json.Marshal(detail)
		detailStr = string(bs)
	}
	now := time.Now()
	return IncidentOperationLog{
		ReadOnlyModel: ReadOnlyModel{
			Id:        ulid.GenerateID(),
			CreatedAt: now,
		},
		IncidentId:    incidentId,
		IncidentNo:    incidentNo,
		OperationType: opType,
		OperatorId:    operatorId,
		OperatorName:  operatorName,
		OperationTime: now,
		Result:        result,
		Detail:        detailStr,
		SourceSystem:  sourceSystem,
	}
}

func BuildIncidentOperationLogWithTime(
	incidentId, incidentNo, opType, operatorId, operatorName, result string,
	detail map[string]interface{},
	sourceSystem string,
	operationTime time.Time,
) IncidentOperationLog {
	detailStr := ""
	if detail != nil {
		bs, _ := json.Marshal(detail)
		detailStr = string(bs)
	}
	return IncidentOperationLog{
		ReadOnlyModel: ReadOnlyModel{
			Id:        ulid.GenerateID(),
			CreatedAt: time.Now(),
		},
		IncidentId:    incidentId,
		IncidentNo:    incidentNo,
		OperationType: opType,
		OperatorId:    operatorId,
		OperatorName:  operatorName,
		OperationTime: operationTime,
		Result:        result,
		Detail:        detailStr,
		SourceSystem:  sourceSystem,
	}
}

func CreateIncidentOperationLog(session *gorm.DB, log IncidentOperationLog) error {
	return session.Create(&log).Error
}

// ─── 事件评论/协同讨论 ───

type IncidentComment struct {
	FullModel
	IncidentId string         `gorm:"type:varchar(80);index;not null;comment:关联事件ID" json:"incident_id"`
	ParentId   string         `gorm:"type:varchar(80);index;default:'';comment:父评论ID(空=顶级)" json:"parent_id"`
	Content    string         `gorm:"type:text;not null;comment:评论内容" json:"content"`
	AuthorId   string         `gorm:"type:varchar(80);comment:作者ID" json:"author_id"`
	AuthorName string         `gorm:"type:varchar(100);comment:作者姓名" json:"author_name"`
	Mentions   string         `gorm:"type:varchar(500);comment:被@的用户ID列表(逗号分隔)" json:"mentions"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (*IncidentComment) TableName() string { return "incident_comments" }

func BuildIncidentComment(incidentId, parentId, content, authorId, authorName, mentions string) IncidentComment {
	now := time.Now()
	return IncidentComment{
		FullModel: FullModel{
			Id:        ulid.GenerateID(),
			CreatedAt: now,
			CreatedBy: authorId,
			UpdatedAt: now,
			UpdatedBy: authorId,
		},
		IncidentId: incidentId,
		ParentId:   parentId,
		Content:    content,
		AuthorId:   authorId,
		AuthorName: authorName,
		Mentions:   mentions,
	}
}

// ─── 事件通知派发记录 ───

type IncidentDispatch struct {
	FullModel
	IncidentId   string  `gorm:"type:varchar(80);index;comment:关联事件ID" json:"incident_id"`
	IncidentNo   string  `gorm:"type:varchar(100);comment:事件编号" json:"incident_no"`
	TemplateId   string  `gorm:"type:varchar(80);comment:使用模板ID" json:"template_id"`
	TemplateName string  `gorm:"type:varchar(255);comment:模板名称快照" json:"template_name"`
	Recipient    string  `gorm:"type:varchar(255);comment:通报接收方" json:"recipient"`
	Content      string  `gorm:"type:text;comment:实际通报内容" json:"content"`
	Status       int     `gorm:"default:1;comment:下发状态" json:"status"`
	DispatchedBy string  `gorm:"type:varchar(100);comment:下发人" json:"dispatched_by"`
	ConfirmedAt  *string `gorm:"type:timestamp;comment:回执确认时间" json:"confirmed_at"`
	ConfirmedBy  string  `gorm:"type:varchar(100);comment:回执确认人" json:"confirmed_by"`
	FailReason   string  `gorm:"type:text;comment:失败原因" json:"fail_reason"`
}

func (IncidentDispatch) TableName() string { return "incident_dispatches" }

// ─── 知识库/案例库文章 ───

type KnowledgeArticle struct {
	FullModel
	Title        string         `gorm:"type:varchar(255);not null;comment:标题" json:"title"`
	Content      string         `gorm:"type:text;comment:正文内容(Markdown)" json:"content"`
	Category     string         `gorm:"type:varchar(100);index;comment:分类(案例/预案/知识)" json:"category"`
	Tags         string         `gorm:"type:varchar(500);comment:标签(逗号分隔)" json:"tags"`
	IncidentId   string         `gorm:"type:varchar(80);index;comment:关联事件ID" json:"incident_id"`
	Level        int            `gorm:"default:0;comment:关联事件等级" json:"level"`
	Source       string         `gorm:"type:varchar(100);comment:来源(manual/auto_archive)" json:"source"`
	ViewCount    int            `gorm:"default:0;comment:浏览次数" json:"view_count"`
	LikeCount    int            `gorm:"default:0;comment:点赞次数" json:"like_count"`
	AuthorId     string         `gorm:"type:varchar(80);comment:作者ID" json:"author_id"`
	AuthorName   string         `gorm:"type:varchar(100);comment:作者姓名" json:"author_name"`
	Summary      string         `gorm:"type:varchar(500);comment:摘要" json:"summary"`
	Solution     string         `gorm:"type:text;comment:解决方案" json:"solution"`
	IncidentType string         `gorm:"type:varchar(100);index;comment:事件类型" json:"incident_type"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (*KnowledgeArticle) TableName() string { return "knowledge_articles" }

// ─── 威胁情报记录 ───

type ThreatIntelRecord struct {
	FullModel
	CveId            string         `gorm:"type:varchar(50);uniqueIndex;comment:CVE编号" json:"cve_id"`
	CnvdId           string         `gorm:"type:varchar(50);index;comment:CNVD编号" json:"cnvd_id"`
	Title            string         `gorm:"type:varchar(500);comment:漏洞标题" json:"title"`
	Description      string         `gorm:"type:text;comment:漏洞描述" json:"description"`
	Severity         string         `gorm:"type:varchar(20);comment:严重等级" json:"severity"`
	CvssV3Score      float64        `gorm:"type:decimal(3,1);comment:CVSS v3评分" json:"cvss_v3_score"`
	AffectedVendor   string         `gorm:"type:varchar(255);comment:受影响厂商" json:"affected_vendor"`
	AffectedProduct  string         `gorm:"type:varchar(255);comment:受影响产品" json:"affected_product"`
	PublishedAt      string         `gorm:"type:varchar(30);comment:发布时间" json:"published_at"`
	AttackVector     string         `gorm:"type:varchar(100);comment:攻击向量" json:"attack_vector"`
	AttackTactics    string         `gorm:"type:varchar(500);comment:ATT&CK战术(逗号分隔)" json:"attack_tactics"`
	AttackTechniques string         `gorm:"type:varchar(500);comment:ATT&CK技术(逗号分隔)" json:"attack_techniques"`
	References       string         `gorm:"type:text;comment:参考链接(JSON数组)" json:"references"`
	Patch            string         `gorm:"type:text;comment:修复建议" json:"patch"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (*ThreatIntelRecord) TableName() string { return "threat_intel_records" }

// ─── 提示词模板 ───

type PromptTemplate struct {
	FullModel
	Name         string         `gorm:"type:varchar(100);not null;uniqueIndex;comment:模板名称" json:"name"`
	Scene        string         `gorm:"type:varchar(50);index;comment:使用场景(ai_preaudit/ai_classify/intel_analysis/custom)" json:"scene"`
	Description  string         `gorm:"type:varchar(500);comment:模板用途说明" json:"description"`
	SystemPrompt string         `gorm:"type:text;comment:系统提示词" json:"system_prompt"`
	UserPrompt   string         `gorm:"type:text;comment:用户提示词模板(支持 {{.变量}} 占位)" json:"user_prompt"`
	OutputFormat string         `gorm:"type:text;comment:期望输出格式示例(JSON Schema等)" json:"output_format"`
	Variables    string         `gorm:"type:varchar(1000);comment:可用模板变量列表(JSON数组)" json:"variables"`
	ModelName    string         `gorm:"type:varchar(100);comment:指定模型名称(空=自动选择)" json:"model_name"`
	Temperature  float64        `gorm:"type:decimal(3,2);default:0.30;comment:生成温度" json:"temperature"`
	MaxTokens    int            `gorm:"default:2000;comment:最大输出token数" json:"max_tokens"`
	Enabled      bool           `gorm:"default:true;comment:是否启用" json:"enabled"`
	IsBuiltin    bool           `gorm:"default:false;comment:是否内置模板" json:"is_builtin"`
	Version      int            `gorm:"default:1;comment:版本号" json:"version"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (*PromptTemplate) TableName() string { return "prompt_templates" }
