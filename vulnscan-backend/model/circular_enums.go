package model

// ─── 通报模板类型 ───

type CircularTemplateType string

const (
	CircularTmpInput    CircularTemplateType = "input"
	CircularTmpDisposal CircularTemplateType = "disposal"
)

// ─── 通报数据来源 ───

type CircularDataSource string

const (
	CircularSourceTemplateImport   CircularDataSource = "template_import"
	CircularSourceManualInput      CircularDataSource = "manual_input"
	CircularSourceThirdPartyImport CircularDataSource = "third_party_import"
	CircularSourceSuperiorTransfer CircularDataSource = "superior_transfer"
)

// ─── 通报状态 ───

type CircularStatus string

const (
	CircularToBeSubmit      CircularStatus = "to_be_submit"
	CircularToBeVerified    CircularStatus = "to_be_verified"
	CircularToBeDistributed CircularStatus = "to_be_distributed"
	CircularToBeProcessed   CircularStatus = "to_be_processed"
	CircularToBeReviewed    CircularStatus = "to_be_reviewed"
	CircularRejected        CircularStatus = "rejected"
	CircularCompleted       CircularStatus = "completed"
	CircularTimeOut         CircularStatus = "time_out"
	CircularInProgress      CircularStatus = "in_progress"
	CircularRedistributed   CircularStatus = "redistributed"
	CircularDisposed        CircularStatus = "disposed"
	CircularReviewed        CircularStatus = "reviewed"
)

// ─── 危害等级 ───

type CircularHazardLevel string

const (
	CircularHazardLow      CircularHazardLevel = "low"
	CircularHazardMedium   CircularHazardLevel = "medium"
	CircularHazardHigh     CircularHazardLevel = "high"
	CircularHazardCritical CircularHazardLevel = "critical"
)

// ─── 预警等级 ───

type CircularWarningLevel string

const (
	CircularGrade1 CircularWarningLevel = "grade1"
	CircularGrade2 CircularWarningLevel = "grade2"
	CircularGrade3 CircularWarningLevel = "grade3"
	CircularGrade4 CircularWarningLevel = "grade4"
)

// ─── 操作类型 ───

type CircularOperationType string

const (
	CircularOpInput            CircularOperationType = "input"
	CircularOpImport           CircularOperationType = "import"
	CircularOpSubmit           CircularOperationType = "submit"
	CircularOpThirdPartyImport CircularOperationType = "third_party_import"
	CircularOpVerifyPass       CircularOperationType = "verify_pass"
	CircularOpVerifyReject     CircularOperationType = "verify_reject"
	CircularOpDistribute       CircularOperationType = "distribute"
	CircularOpRedistribute     CircularOperationType = "redistribute"
	CircularOpDisposal         CircularOperationType = "disposal"
	CircularOpReviewApprove    CircularOperationType = "review_approve"
	CircularOpReviewReject     CircularOperationType = "review_reject"
	CircularOpCompleted        CircularOperationType = "completed"
)

// ─── 涉密等级 ───

type CircularSecurityLevel string

const (
	CircularSecLevel1 CircularSecurityLevel = "level1"
	CircularSecLevel2 CircularSecurityLevel = "level2"
	CircularSecLevel3 CircularSecurityLevel = "level3"
	CircularSecLevel4 CircularSecurityLevel = "level4"
	CircularSecLevel5 CircularSecurityLevel = "level5"
)

// ─── 等级映射表 ───

var CircularSecurityLevelMap = map[CircularSecurityLevel]string{
	CircularSecLevel1: "一级", CircularSecLevel2: "二级", CircularSecLevel3: "三级",
	CircularSecLevel4: "四级", CircularSecLevel5: "五级",
}

var CircularDangerLevelMap = map[CircularHazardLevel]string{
	CircularHazardLow: "低危", CircularHazardMedium: "中危",
	CircularHazardHigh: "高危", CircularHazardCritical: "危急",
}

var CircularWarningLevelMap = map[CircularWarningLevel]string{
	CircularGrade1: "一级", CircularGrade2: "二级",
	CircularGrade3: "三级", CircularGrade4: "四级",
}

var StringToCircularSecurityMap = map[string]CircularSecurityLevel{
	"一级": CircularSecLevel1, "二级": CircularSecLevel2, "三级": CircularSecLevel3,
	"四级": CircularSecLevel4, "五级": CircularSecLevel5,
}

var StringToCircularDangerMap = map[string]CircularHazardLevel{
	"低危": CircularHazardLow, "中危": CircularHazardMedium,
	"高危": CircularHazardHigh, "危急": CircularHazardCritical,
}

var StringToCircularWarningMap = map[string]CircularWarningLevel{
	"一级": CircularGrade1, "二级": CircularGrade2,
	"三级": CircularGrade3, "四级": CircularGrade4,
}
