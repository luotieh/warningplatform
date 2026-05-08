package transferContract

import "context"

type TransferAssetInfo struct {
	AssetName    string `json:"asset_name"`
	SystemName   string `json:"system_name"`
	DomainIP     string `json:"domain_ip"`
	SiteIP       string `json:"site_ip"`
	Unit         string `json:"unit"`
	UnitType     string `json:"unit_type"`
	Industry     string `json:"industry"`
	MLPSRecordNo string `json:"mlps_record_no"`
	MLPSLevel    string `json:"mlps_level"`
	Region       string `json:"region"`
}

type TransferMetadataInfo struct {
	DataNo              string  `json:"data_no"`
	IncidentType        string  `json:"incident_type"`
	IncidentURL         string  `json:"incident_url"`
	IncidentDescription string  `json:"incident_description"`
	CvssScore           float64 `json:"cvss_score"`
	CveId               string  `json:"cve_id"`
}

type TransferIncidentReq struct {
	IncidentNo   string                `json:"incident_no" binding:"required"`
	Name         string                `json:"name" binding:"required"`
	Level        int                   `json:"level"`
	AiOpinion    string                `json:"ai_opinion"`
	AiConfidence float64               `json:"ai_confidence"`
	AssetInfo    *TransferAssetInfo    `json:"asset_info"`
	MetadataInfo *TransferMetadataInfo `json:"metadata_info"`
	SourceSystem string                `json:"source_system"`
}

type TransferIncidentBatchReq struct {
	Incidents []TransferIncidentReq `json:"incidents" binding:"required,min=1"`
}

type TransferResultItem struct {
	IncidentNo   string `json:"incident_no"`
	CircularCode string `json:"circular_code"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

type TransferStatusResp struct {
	IncidentNo   string `json:"incident_no"`
	CircularId   string `json:"circular_id"`
	CircularCode string `json:"circular_code"`
	Status       string `json:"status"`
	TransferTime string `json:"transfer_time"`
}

type ServiceTransfer interface {
	ReceiveIncident(ctx context.Context, req TransferIncidentReq, createdBy string) (string, error)
	ReceiveIncidentBatch(ctx context.Context, req TransferIncidentBatchReq, createdBy string) ([]TransferResultItem, error)
	GetTransferStatus(ctx context.Context, incidentNo string) (*TransferStatusResp, error)
}
