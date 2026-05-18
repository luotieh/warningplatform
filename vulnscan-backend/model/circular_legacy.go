package model

// Deprecated: 旧版通报关联模型，仅用于历史导入导出兼容。
// 请使用 Circular + DynamicFormSubmission 替代。
// 这些模型不在 AutoMigrate 列表中，不会创建新表。

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
