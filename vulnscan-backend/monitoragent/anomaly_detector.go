package monitoragent

import (
	"fmt"
	"math"
)

type AnomalyResult struct {
	IsAnomaly   bool            `json:"is_anomaly"`
	Score       float64         `json:"score"`
	Level       string          `json:"level"`
	Anomalies   []AnomalyDetail `json:"anomalies,omitempty"`
	Suggestions []string        `json:"suggestions,omitempty"`
}

type AnomalyDetail struct {
	Metric    string  `json:"metric"`
	Current   float64 `json:"current"`
	Baseline  float64 `json:"baseline"`
	Deviation float64 `json:"deviation"`
	Severity  string  `json:"severity"`
	Message   string  `json:"message"`
}

type BaselineData struct {
	AvgDNSMS      float64
	AvgTTFBMS     float64
	AvgTotalMS    float64
	AvgContentLen int
	SampleCount   int
	P95TotalMS    float64
	MaxTotalMS    float64
	MinTotalMS    float64
}

type CurrentMetrics struct {
	DNSMS      float64
	TTFBMS     float64
	TotalMS    float64
	ContentLen int
	StatusCode int
	Available  bool
}

func DetectAnomalies(baseline *BaselineData, current *CurrentMetrics) *AnomalyResult {
	result := &AnomalyResult{
		Score: 0,
		Level: "normal",
	}

	if baseline == nil || baseline.SampleCount < 3 {
		return result
	}

	if !current.Available {
		result.IsAnomaly = true
		result.Score = 100
		result.Level = "critical"
		result.Anomalies = append(result.Anomalies, AnomalyDetail{
			Metric:   "availability",
			Severity: "critical",
			Message:  "站点不可用",
		})
		return result
	}

	if current.StatusCode >= 500 {
		result.IsAnomaly = true
		result.Score = 80
		result.Level = "high"
		result.Anomalies = append(result.Anomalies, AnomalyDetail{
			Metric:   "status_code",
			Current:  float64(current.StatusCode),
			Severity: "high",
			Message:  "服务器内部错误",
		})
	}

	thresholds := []struct {
		Name     string
		Current  float64
		Baseline float64
		Weight   float64
	}{
		{"dns_ms", current.DNSMS, baseline.AvgDNSMS, 10},
		{"ttfb_ms", current.TTFBMS, baseline.AvgTTFBMS, 25},
		{"total_ms", current.TotalMS, baseline.AvgTotalMS, 30},
		{"content_len", float64(current.ContentLen), float64(baseline.AvgContentLen), 20},
	}

	totalWeight := 0.0
	weightedScore := 0.0

	for _, t := range thresholds {
		if t.Baseline <= 0 {
			continue
		}

		deviation := (t.Current - t.Baseline) / t.Baseline
		absDeviation := math.Abs(deviation)

		var severity string
		var metricScore float64

		switch {
		case absDeviation > 3.0:
			severity = "critical"
			metricScore = 100
		case absDeviation > 2.0:
			severity = "high"
			metricScore = 75
		case absDeviation > 1.0:
			severity = "medium"
			metricScore = 50
		case absDeviation > 0.5:
			severity = "low"
			metricScore = 25
		default:
			continue
		}

		result.Anomalies = append(result.Anomalies, AnomalyDetail{
			Metric:    t.Name,
			Current:   t.Current,
			Baseline:  t.Baseline,
			Deviation: deviation * 100,
			Severity:  severity,
			Message:   anomalyMessage(t.Name, deviation),
		})

		weightedScore += metricScore * t.Weight
		totalWeight += t.Weight
	}

	if totalWeight > 0 {
		result.Score = weightedScore / totalWeight
	}

	switch {
	case result.Score >= 80:
		result.Level = "critical"
		result.IsAnomaly = true
	case result.Score >= 60:
		result.Level = "high"
		result.IsAnomaly = true
	case result.Score >= 40:
		result.Level = "medium"
		result.IsAnomaly = true
	case result.Score >= 20:
		result.Level = "low"
		result.IsAnomaly = true
	}

	result.Suggestions = generateSuggestions(result)
	return result
}

func anomalyMessage(metric string, deviation float64) string {
	direction := "上升"
	if deviation < 0 {
		direction = "下降"
	}
	pct := math.Abs(deviation) * 100

	names := map[string]string{
		"dns_ms":      "DNS解析耗时",
		"ttfb_ms":     "首字节响应时间",
		"total_ms":    "总响应时间",
		"content_len": "页面内容大小",
	}

	name := names[metric]
	if name == "" {
		name = metric
	}

	pctStr := ""
	if pct >= 1000 {
		pctStr = ">1000%"
	} else {
		pctStr = fmt.Sprintf("%.1f%%", pct)
	}

	return fmt.Sprintf("%s较基线%s%s", name, direction, pctStr)
}

func generateSuggestions(result *AnomalyResult) []string {
	var suggestions []string

	for _, a := range result.Anomalies {
		switch a.Metric {
		case "dns_ms":
			if a.Deviation > 100 {
				suggestions = append(suggestions, "DNS解析异常缓慢，检查DNS服务器状态或是否存在DNS劫持")
			}
		case "ttfb_ms":
			if a.Deviation > 100 {
				suggestions = append(suggestions, "服务器响应变慢，检查后端服务器负载和网络连接")
			}
		case "total_ms":
			if a.Deviation > 100 {
				suggestions = append(suggestions, "页面加载时间异常，可能存在性能问题或网络中断")
			}
		case "content_len":
			if a.Deviation < -50 {
				suggestions = append(suggestions, "页面内容大幅减少，可能存在篡改或服务降级")
			}
			if a.Deviation > 200 {
				suggestions = append(suggestions, "页面内容异常增加，可能被注入了恶意内容")
			}
		case "availability":
			suggestions = append(suggestions, "站点不可用，立即检查服务器状态和网络连接")
		}
	}

	return suggestions
}

func ComputeRiskScore(execResults map[string]bool, anomaly *AnomalyResult, perfDeviation float64) (float64, string) {
	score := 0.0

	dimWeights := map[string]float64{
		"availability":   30,
		"tamper":         25,
		"blacklink":      15,
		"domain_hijack":  15,
		"sensitive_word": 8,
		"sensitive_file": 7,
	}

	for dim, hasIssue := range execResults {
		if hasIssue {
			score += dimWeights[dim]
		}
	}

	if anomaly != nil && anomaly.IsAnomaly {
		score += anomaly.Score * 0.15
	}

	if perfDeviation > 2.0 {
		score += 5
	}

	if score > 100 {
		score = 100
	}

	var level string
	switch {
	case score >= 80:
		level = "critical"
	case score >= 60:
		level = "high"
	case score >= 40:
		level = "medium"
	case score >= 20:
		level = "low"
	default:
		level = "safe"
	}

	return score, level
}
