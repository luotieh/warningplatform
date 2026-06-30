package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TransferIncidentReq 对齐 circular/transfer 的请求体（json tag 与 circular contract 一致）。
// 在 traffic 侧本地定义以避免跨模块 import。
type TransferIncidentReq struct {
	IncidentID   string                `json:"incident_id,omitempty"`
	IncidentNo   string                `json:"incident_no"`
	Name         string                `json:"name"`
	Level        int                   `json:"level,omitempty"`
	AiOpinion    string                `json:"ai_opinion,omitempty"`
	AiConfidence float64               `json:"ai_confidence,omitempty"`
	AssetInfo    *TransferAssetInfo    `json:"asset_info,omitempty"`
	MetadataInfo *TransferMetadataInfo `json:"metadata_info,omitempty"`
	SourceSystem string                `json:"source_system,omitempty"`
}

type TransferAssetInfo struct {
	AssetName    string `json:"asset_name,omitempty"`
	SystemName   string `json:"system_name,omitempty"`
	DomainIP     string `json:"domain_ip,omitempty"`
	SiteIP       string `json:"site_ip,omitempty"`
	Unit         string `json:"unit,omitempty"`
	UnitType     string `json:"unit_type,omitempty"`
	Industry     string `json:"industry,omitempty"`
	MLPSRecordNo string `json:"mlps_record_no,omitempty"`
	MLPSLevel    string `json:"mlps_level,omitempty"`
	Region       string `json:"region,omitempty"`
}

type TransferMetadataInfo struct {
	DataNo              string  `json:"data_no,omitempty"`
	IncidentType        string  `json:"incident_type,omitempty"`
	IncidentURL         string  `json:"incident_url,omitempty"`
	IncidentDescription string  `json:"incident_description,omitempty"`
	CvssScore           float64 `json:"cvss_score,omitempty"`
	CveId               string  `json:"cve_id,omitempty"`
}

// CircularClient 调用通报处置「安全事件流转」接口。
type CircularClient struct {
	BaseURL string // 配置项；留空则使用 ReceiveIncident 传入的 fallbackBase
	HTTP    *http.Client
}

// ReceiveIncident POST {base}/api/circular/transfers，透传调用方的 bearer。
// 返回通报处置生成的 circular_code。
func (c CircularClient) ReceiveIncident(ctx context.Context, req TransferIncidentReq, bearer, fallbackBase string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(fallbackBase), "/")
	}
	if base == "" {
		return "", errors.New("circular base url is empty")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/circular/transfers", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(bearer) != "" {
		httpReq.Header.Set("Authorization", bearer)
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			CircularCode string `json:"circular_code"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("circular transfer failed: status=%d msg=%s", resp.StatusCode, out.Msg)
	}
	return out.Data.CircularCode, nil
}
