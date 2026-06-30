package traffic

import (
	"encoding/json"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/domain"
)

const circularSourceSystem = "流量分析(trafficAnalysis)"

// buildTransferIncidentReq 把流量分析事件映射为通报处置「安全事件流转」请求体。
func buildTransferIncidentReq(event domain.Event, summaries []domain.Summary) client.TransferIncidentReq {
	ctx := map[string]any{}
	if event.Context != "" {
		_ = json.Unmarshal([]byte(event.Context), &ctx)
	}

	source, destination := observablePair(event.Observables)
	source = firstNonEmpty(source, stringValue(ctx["threat_source"]), stringValue(ctx["src_ip"]))
	destination = firstNonEmpty(destination, stringValue(ctx["victim_target"]), stringValue(ctx["dst_ip"]))

	name := firstNonEmpty(event.Title, event.EventName)
	if name == "" {
		name = "流量分析事件 " + event.EventID
	}

	aiOpinion := ""
	if len(summaries) > 0 {
		aiOpinion = summaries[len(summaries)-1].EventSummary
	}
	if aiOpinion == "" {
		aiOpinion = event.Message
	}

	req := client.TransferIncidentReq{
		IncidentNo:   event.EventID,
		Name:         name,
		Level:        severityToLevel(event.Severity),
		AiOpinion:    aiOpinion,
		AiConfidence: floatValue(ctx["ai_confidence"]),
		SourceSystem: circularSourceSystem,
		AssetInfo: &client.TransferAssetInfo{
			AssetName:  firstNonEmpty(stringValue(ctx["victim_target"]), destination),
			SystemName: stringValue(ctx["system_name"]),
			DomainIP:   firstNonEmpty(stringValue(ctx["dst_domain"]), destination),
			SiteIP:     destination,
			Region:     stringValue(ctx["region"]),
		},
		MetadataInfo: &client.TransferMetadataInfo{
			IncidentType:        firstNonEmpty(event.Category, stringValue(ctx["event_type"]), stringValue(ctx["type"])),
			IncidentURL:         stringValue(ctx["incident_url"]),
			IncidentDescription: firstNonEmpty(event.Message, event.Title),
			CveId:               stringValue(ctx["cve_id"]),
			CvssScore:           floatValue(ctx["cvss_score"]),
		},
	}
	return req
}

// severityToLevel 把流量事件 severity 映射到通报处置 Level：1特别重大/2重大/3较大/4一般。
func severityToLevel(severity string) int {
	switch severity {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium", "middle":
		return 3
	case "low":
		return 4
	default:
		return 4
	}
}

func floatValue(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return 0
	}
}
