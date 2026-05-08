package remediationContract

import (
	"context"
	"time"

	coreContract "vulnscan-backend/incident/core/core-contract"
)

type ServiceRemediation interface {
	SubmitRemediation(ctx context.Context, req RemediationReq) error
	VerifyRemediation(ctx context.Context, req VerifyRemediationReq) error
	CloseIncident(ctx context.Context, req CloseIncidentReq) error
	BatchImport(ctx context.Context, records []IncidentImportRow, createdBy string) (*BatchImportResp, error)
}

type RemediationReq struct {
	ID                  string     `json:"id" binding:"required"`
	RemediationPlan     string     `json:"remediation_plan" binding:"required"`
	RemediationDeadline *time.Time `json:"remediation_deadline"`
	RemediationAssignee string     `json:"remediation_assignee"`
}

type VerifyRemediationReq struct {
	ID     string `json:"id" binding:"required"`
	Result string `json:"result" binding:"required,oneof=pass reject"`
	Remark string `json:"remark"`
}

type CloseIncidentReq struct {
	ID          string `json:"id" binding:"required"`
	CloseReason string `json:"close_reason"`
}

type IncidentImportRow struct {
	Name          string  `json:"name"`
	Level         int     `json:"level"`
	Source        int     `json:"source"`
	AssetName     string  `json:"asset_name"`
	SystemName    string  `json:"system_name"`
	DomainIP      string  `json:"domain_ip"`
	Unit          string  `json:"unit"`
	IncidentType  string  `json:"incident_type"`
	CvssScore     float64 `json:"cvss_score"`
	CveId         string  `json:"cve_id"`
	OwaspCategory string  `json:"owasp_category"`
	ExploitDiff   string  `json:"exploit_difficulty"`
	AffectScope   string  `json:"affect_scope"`
	IncidentURL   string  `json:"incident_url"`
	Description   string  `json:"description"`
	VendorName    string  `json:"vendor_name"`
	DiscoveryTime string  `json:"discovery_time"`
}

type BatchImportResp struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
}

type ExportBatchReq struct {
	IDs    []string `json:"ids" binding:"required"`
	Format string   `json:"format" binding:"required,oneof=csv excel"`
}

type ExportSingleReq struct {
	ID     string `form:"id" binding:"required"`
	Format string `form:"format" binding:"required,oneof=word pdf"`
}

func ToCreateReq(row IncidentImportRow) coreContract.IncidentCreateReq {
	return coreContract.IncidentCreateReq{
		Name:   row.Name,
		Level:  row.Level,
		Source: row.Source,
		Asset: coreContract.IncidentAssetReq{
			AssetName:  row.AssetName,
			SystemName: row.SystemName,
			DomainIP:   row.DomainIP,
			Unit:       row.Unit,
		},
		Metadata: coreContract.IncidentMetaReq{
			IncidentType:        row.IncidentType,
			IncidentURL:         row.IncidentURL,
			IncidentDescription: row.Description,
			VendorName:          row.VendorName,
			CvssScore:           row.CvssScore,
			CveId:               row.CveId,
			OwaspCategory:       row.OwaspCategory,
			ExploitDifficulty:   row.ExploitDiff,
			AffectScope:         row.AffectScope,
		},
	}
}
