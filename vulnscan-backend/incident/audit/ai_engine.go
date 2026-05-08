package audit

import (
	"fmt"
	"math"
	"strings"
	"time"
	"vulnscan-backend/model"

	auditContract "vulnscan-backend/incident/audit/audit-contract"
	coreContract "vulnscan-backend/incident/core/core-contract"
	statsContract "vulnscan-backend/incident/stats/stats-contract"
)

// CalculateRiskScore evaluates a security incident across 5 dimensions and returns
// a composite risk score (0-100) along with per-dimension breakdowns.
//
// Dimensions and max scores:
//   - CVSS (max 30): based on EventMetadata.CvssScore
//   - ExploitDifficulty (max 20): based on EventMetadata.ExploitDifficulty
//   - Scope (max 15): based on EventMetadata.AffectScope
//   - Level (max 20): based on incident.Level
//   - OWASP (max 15): based on EventMetadata.OwaspCategory
func CalculateRiskScore(incident *model.SecurityIncident) auditContract.RiskScoreResult {
	var breakdowns []auditContract.RiskBreakdown
	var totalScore float64

	// 1. CVSS dimension (max 30)
	cvssScore, cvssReason := calcCvssDimension(incident)
	breakdowns = append(breakdowns, auditContract.RiskBreakdown{
		Dimension: "CVSS评分", Score: cvssScore, MaxScore: 30, Reason: cvssReason,
	})
	totalScore += cvssScore

	// 2. Exploit difficulty dimension (max 20)
	exploitScore, exploitReason := calcExploitDimension(incident)
	breakdowns = append(breakdowns, auditContract.RiskBreakdown{
		Dimension: "利用难度", Score: exploitScore, MaxScore: 20, Reason: exploitReason,
	})
	totalScore += exploitScore

	// 3. Scope dimension (max 15)
	scopeScore, scopeReason := calcScopeDimension(incident)
	breakdowns = append(breakdowns, auditContract.RiskBreakdown{
		Dimension: "影响范围", Score: scopeScore, MaxScore: 15, Reason: scopeReason,
	})
	totalScore += scopeScore

	// 4. Level dimension (max 20)
	levelScore, levelReason := calcLevelDimension(incident)
	breakdowns = append(breakdowns, auditContract.RiskBreakdown{
		Dimension: "事件等级", Score: levelScore, MaxScore: 20, Reason: levelReason,
	})
	totalScore += levelScore

	// 5. OWASP dimension (max 15)
	owaspScore, owaspReason := calcOwaspDimension(incident)
	breakdowns = append(breakdowns, auditContract.RiskBreakdown{
		Dimension: "OWASP分类", Score: owaspScore, MaxScore: 15, Reason: owaspReason,
	})
	totalScore += owaspScore

	level := determineRiskLevel(totalScore)
	tags := generateTags(incident)
	category := generateCategory(incident)
	recommendations := generateRecommendations(incident, totalScore)

	return auditContract.RiskScoreResult{
		TotalScore:      math.Round(totalScore*100) / 100,
		Level:           level,
		CvssWeight:      cvssScore,
		ExploitWeight:   exploitScore,
		ScopeWeight:     scopeScore,
		LevelWeight:     levelScore,
		OwaspWeight:     owaspScore,
		BreakdownItems:  breakdowns,
		Recommendations: recommendations,
		Tags:            tags,
		Category:        category,
	}
}

func calcCvssDimension(incident *model.SecurityIncident) (float64, string) {
	if incident.EventMetadata == nil {
		return 0, "无CVSS评分数据"
	}
	cvss := incident.EventMetadata.CvssScore
	if cvss <= 0 {
		return 0, "CVSS评分为0或未提供"
	}
	// Map CVSS 0-10 to 0-30
	score := (cvss / 10.0) * 30.0
	if score > 30 {
		score = 30
	}
	reason := fmt.Sprintf("CVSS评分%.1f，映射得分%.1f/30", cvss, score)
	return math.Round(score*100) / 100, reason
}

func calcExploitDimension(incident *model.SecurityIncident) (float64, string) {
	if incident.EventMetadata == nil {
		return 5, "无利用难度数据，默认中等风险"
	}
	difficulty := strings.ToLower(incident.EventMetadata.ExploitDifficulty)
	switch {
	case containsAny(difficulty, "low", "easy", "低", "容易"):
		return 20, "利用难度低，风险极高"
	case containsAny(difficulty, "medium", "moderate", "中", "一般"):
		return 12, "利用难度中等"
	case containsAny(difficulty, "high", "hard", "difficult", "高", "困难"):
		return 5, "利用难度高，风险较低"
	default:
		return 10, fmt.Sprintf("利用难度未知(%s)，取中间值", incident.EventMetadata.ExploitDifficulty)
	}
}

func calcScopeDimension(incident *model.SecurityIncident) (float64, string) {
	if incident.EventMetadata == nil {
		return 5, "无影响范围数据，默认中等"
	}
	scope := strings.ToLower(incident.EventMetadata.AffectScope)
	if scope == "" {
		return 5, "影响范围未填写，默认中等"
	}
	switch {
	case containsAny(scope, "全网", "全部", "所有", "critical", "全局", "整体"):
		return 15, "影响范围极广，涉及全网/全部系统"
	case containsAny(scope, "多个", "大量", "广泛", "major", "大范围"):
		return 12, "影响范围较广，涉及多个系统"
	case containsAny(scope, "部分", "局部", "moderate", "中等"):
		return 8, "影响范围中等，涉及部分系统"
	case containsAny(scope, "单个", "个别", "少量", "minor", "有限"):
		return 4, "影响范围有限，仅涉及个别系统"
	default:
		return 7, fmt.Sprintf("影响范围描述(%s)，取默认值", incident.EventMetadata.AffectScope)
	}
}

func calcLevelDimension(incident *model.SecurityIncident) (float64, string) {
	switch incident.Level {
	case model.IncidentLevelUrgent:
		return 20, "紧急事件，风险最高"
	case model.IncidentLevelHigh:
		return 15, "高危事件"
	case model.IncidentLevelMedium:
		return 10, "中危事件"
	case model.IncidentLevelLow:
		return 5, "低危事件"
	default:
		return 5, "未知事件等级，按低危处理"
	}
}

func calcOwaspDimension(incident *model.SecurityIncident) (float64, string) {
	if incident.EventMetadata == nil {
		return 5, "无OWASP分类数据"
	}
	category := strings.ToLower(incident.EventMetadata.OwaspCategory)
	if category == "" {
		return 5, "OWASP分类未填写"
	}
	switch {
	case containsAny(category, "injection", "注入", "a03"):
		return 15, "OWASP注入类漏洞，高风险"
	case containsAny(category, "broken access", "访问控制", "a01"):
		return 14, "OWASP访问控制失效，高风险"
	case containsAny(category, "cryptographic", "加密", "a02"):
		return 13, "OWASP加密失败，较高风险"
	case containsAny(category, "insecure design", "不安全设计", "a04"):
		return 12, "OWASP不安全设计"
	case containsAny(category, "misconfiguration", "配置错误", "a05"):
		return 10, "OWASP安全配置错误"
	case containsAny(category, "vulnerable", "过时组件", "a06"):
		return 11, "OWASP使用含漏洞的组件"
	case containsAny(category, "authentication", "认证", "a07"):
		return 12, "OWASP身份认证失败"
	case containsAny(category, "integrity", "完整性", "a08"):
		return 10, "OWASP软件和数据完整性问题"
	case containsAny(category, "logging", "日志", "a09"):
		return 7, "OWASP日志和监控不足"
	case containsAny(category, "ssrf", "服务端请求伪造", "a10"):
		return 11, "OWASP服务端请求伪造"
	default:
		return 8, fmt.Sprintf("OWASP分类(%s)，取默认值", incident.EventMetadata.OwaspCategory)
	}
}

func determineRiskLevel(score float64) string {
	switch {
	case score >= 80:
		return "极高风险"
	case score >= 60:
		return "高风险"
	case score >= 40:
		return "中等风险"
	case score >= 20:
		return "低风险"
	default:
		return "极低风险"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func generateTags(incident *model.SecurityIncident) []string {
	var tags []string

	// Tag by level
	switch incident.Level {
	case model.IncidentLevelUrgent:
		tags = append(tags, "紧急")
	case model.IncidentLevelHigh:
		tags = append(tags, "高危")
	case model.IncidentLevelMedium:
		tags = append(tags, "中危")
	case model.IncidentLevelLow:
		tags = append(tags, "低危")
	}

	if incident.EventMetadata != nil {
		// Tag by CVE
		if incident.EventMetadata.CveId != "" {
			tags = append(tags, "CVE关联")
		}

		// Tag by CVSS
		if incident.EventMetadata.CvssScore >= 9.0 {
			tags = append(tags, "CVSS极高")
		} else if incident.EventMetadata.CvssScore >= 7.0 {
			tags = append(tags, "CVSS高")
		}

		// Tag by exploit difficulty
		difficulty := strings.ToLower(incident.EventMetadata.ExploitDifficulty)
		if containsAny(difficulty, "low", "easy", "低", "容易") {
			tags = append(tags, "易利用")
		}

		// Tag by OWASP
		if incident.EventMetadata.OwaspCategory != "" {
			tags = append(tags, "OWASP")
		}

		// Tag by incident type
		incType := strings.ToLower(incident.EventMetadata.IncidentType)
		if containsAny(incType, "漏洞", "vulnerability") {
			tags = append(tags, "漏洞类")
		}
		if containsAny(incType, "数据泄露", "data leak", "信息泄露") {
			tags = append(tags, "数据泄露")
		}
		if containsAny(incType, "入侵", "intrusion", "攻击", "attack") {
			tags = append(tags, "入侵攻击")
		}

		// Tag by URL
		if incident.EventMetadata.IncidentURL != "" {
			tags = append(tags, "有URL")
		}
	}

	if len(tags) == 0 {
		tags = append(tags, "待分析")
	}
	return tags
}

func generateCategory(incident *model.SecurityIncident) string {
	if incident.EventMetadata == nil {
		return "未分类"
	}

	incType := strings.ToLower(incident.EventMetadata.IncidentType)
	owasp := strings.ToLower(incident.EventMetadata.OwaspCategory)

	switch {
	case containsAny(incType, "漏洞", "vulnerability", "vuln"):
		if containsAny(owasp, "injection", "注入") {
			return "注入漏洞"
		}
		if containsAny(owasp, "xss", "跨站脚本") {
			return "XSS漏洞"
		}
		if containsAny(owasp, "authentication", "认证") {
			return "认证漏洞"
		}
		return "安全漏洞"
	case containsAny(incType, "数据泄露", "data leak", "信息泄露"):
		return "数据泄露"
	case containsAny(incType, "入侵", "intrusion"):
		return "入侵事件"
	case containsAny(incType, "恶意", "malware", "病毒", "木马"):
		return "恶意软件"
	case containsAny(incType, "ddos", "拒绝服务"):
		return "DDoS攻击"
	case containsAny(incType, "钓鱼", "phishing"):
		return "钓鱼攻击"
	case containsAny(incType, "配置", "misconfiguration"):
		return "安全配置问题"
	case containsAny(incType, "篡改", "deface", "tamper"):
		return "网页篡改"
	default:
		if incident.EventMetadata.IncidentType != "" {
			return incident.EventMetadata.IncidentType
		}
		return "未分类"
	}
}

func generateRecommendations(incident *model.SecurityIncident, totalScore float64) []string {
	var recs []string

	if totalScore >= 80 {
		recs = append(recs, "风险评分极高，建议立即启动应急响应流程")
		recs = append(recs, "建议通知安全团队负责人及相关管理层")
	} else if totalScore >= 60 {
		recs = append(recs, "风险评分较高，建议优先处理")
	}

	if incident.EventMetadata != nil {
		if incident.EventMetadata.CvssScore >= 9.0 {
			recs = append(recs, "CVSS评分极高，建议立即修补相关漏洞")
		} else if incident.EventMetadata.CvssScore >= 7.0 {
			recs = append(recs, "CVSS评分较高，建议尽快安排修补")
		}

		difficulty := strings.ToLower(incident.EventMetadata.ExploitDifficulty)
		if containsAny(difficulty, "low", "easy", "低", "容易") {
			recs = append(recs, "漏洞利用难度低，被攻击风险大，建议提高处置优先级")
		}

		if incident.EventMetadata.CveId != "" {
			recs = append(recs, fmt.Sprintf("关联CVE编号%s，建议查阅官方公告获取修复方案", incident.EventMetadata.CveId))
		}

		incType := strings.ToLower(incident.EventMetadata.IncidentType)
		if containsAny(incType, "数据泄露", "data leak", "信息泄露") {
			recs = append(recs, "涉及数据泄露，建议评估泄露范围并启动数据保护预案")
		}
		if containsAny(incType, "入侵", "intrusion", "攻击", "attack") {
			recs = append(recs, "涉及入侵攻击，建议进行溯源分析并加固防护措施")
		}
	}

	if incident.Level == model.IncidentLevelUrgent {
		recs = append(recs, "事件等级为紧急，建议在4小时内完成初步响应")
	} else if incident.Level == model.IncidentLevelHigh {
		recs = append(recs, "事件等级为高危，建议在8小时内完成初步响应")
	}

	if len(recs) == 0 {
		recs = append(recs, "建议按照标准流程进行审核和处置")
	}

	return recs
}

// ClassifyIncident classifies a security incident based on its metadata and returns
// a structured classification result with category, suggested level, tags, and reasoning.
func ClassifyIncident(incident *model.SecurityIncident) auditContract.ClassifyResult {
	category := generateCategory(incident)
	tags := generateTags(incident)
	suggestedLevel := suggestLevel(incident)
	confidence := calcClassifyConfidence(incident)
	reasoning := buildClassifyReasoning(incident, category, suggestedLevel)

	return auditContract.ClassifyResult{
		Category:       category,
		SuggestedLevel: suggestedLevel,
		Tags:           tags,
		Confidence:     confidence,
		Reasoning:      reasoning,
	}
}

func suggestLevel(incident *model.SecurityIncident) int {
	if incident.EventMetadata == nil {
		return incident.Level
	}

	cvss := incident.EventMetadata.CvssScore
	difficulty := strings.ToLower(incident.EventMetadata.ExploitDifficulty)

	// High CVSS + easy exploit = urgent
	if cvss >= 9.0 && containsAny(difficulty, "low", "easy", "低", "容易") {
		return model.IncidentLevelUrgent
	}
	if cvss >= 9.0 {
		return model.IncidentLevelHigh
	}
	if cvss >= 7.0 {
		if containsAny(difficulty, "low", "easy", "低", "容易") {
			return model.IncidentLevelHigh
		}
		return model.IncidentLevelMedium
	}
	if cvss >= 4.0 {
		return model.IncidentLevelMedium
	}
	if cvss > 0 {
		return model.IncidentLevelLow
	}

	return incident.Level
}

func calcClassifyConfidence(incident *model.SecurityIncident) float64 {
	confidence := 0.5
	if incident.EventMetadata != nil {
		if incident.EventMetadata.CvssScore > 0 {
			confidence += 0.15
		}
		if incident.EventMetadata.ExploitDifficulty != "" {
			confidence += 0.1
		}
		if incident.EventMetadata.OwaspCategory != "" {
			confidence += 0.1
		}
		if incident.EventMetadata.IncidentType != "" {
			confidence += 0.1
		}
		if incident.EventMetadata.CveId != "" {
			confidence += 0.05
		}
	}
	if confidence > 0.95 {
		confidence = 0.95
	}
	return math.Round(confidence*100) / 100
}

func buildClassifyReasoning(incident *model.SecurityIncident, category string, suggestedLevel int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("事件分类为[%s]", category))

	levelText, ok := model.IncidentLevelText[suggestedLevel]
	if !ok {
		levelText = "未知"
	}
	parts = append(parts, fmt.Sprintf("建议等级为[%s]", levelText))

	if incident.EventMetadata != nil {
		if incident.EventMetadata.CvssScore > 0 {
			parts = append(parts, fmt.Sprintf("CVSS评分%.1f", incident.EventMetadata.CvssScore))
		}
		if incident.EventMetadata.ExploitDifficulty != "" {
			parts = append(parts, fmt.Sprintf("利用难度[%s]", incident.EventMetadata.ExploitDifficulty))
		}
		if incident.EventMetadata.OwaspCategory != "" {
			parts = append(parts, fmt.Sprintf("OWASP类别[%s]", incident.EventMetadata.OwaspCategory))
		}
		if incident.EventMetadata.CveId != "" {
			parts = append(parts, fmt.Sprintf("关联CVE[%s]", incident.EventMetadata.CveId))
		}
	}

	return strings.Join(parts, "，") + "。"
}

// GenerateStructuredOpinion creates a human-readable AI audit opinion text
// based on the incident details and risk score result.
func GenerateStructuredOpinion(incident *model.SecurityIncident, result auditContract.RiskScoreResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("【AI预审意见】\n"))
	sb.WriteString(fmt.Sprintf("事件名称：%s\n", incident.Name))
	sb.WriteString(fmt.Sprintf("事件编号：%s\n", incident.IncidentNo))
	sb.WriteString(fmt.Sprintf("综合风险评分：%.1f/100（%s）\n\n", result.TotalScore, result.Level))

	sb.WriteString("【各维度评分】\n")
	for _, bd := range result.BreakdownItems {
		sb.WriteString(fmt.Sprintf("  - %s：%.1f/%.0f — %s\n", bd.Dimension, bd.Score, bd.MaxScore, bd.Reason))
	}
	sb.WriteString("\n")

	if incident.EventMetadata != nil {
		sb.WriteString("【关键信息】\n")
		if incident.EventMetadata.CveId != "" {
			sb.WriteString(fmt.Sprintf("  - CVE编号：%s\n", incident.EventMetadata.CveId))
		}
		if incident.EventMetadata.CvssScore > 0 {
			sb.WriteString(fmt.Sprintf("  - CVSS评分：%.1f\n", incident.EventMetadata.CvssScore))
		}
		if incident.EventMetadata.OwaspCategory != "" {
			sb.WriteString(fmt.Sprintf("  - OWASP分类：%s\n", incident.EventMetadata.OwaspCategory))
		}
		if incident.EventMetadata.ExploitDifficulty != "" {
			sb.WriteString(fmt.Sprintf("  - 利用难度：%s\n", incident.EventMetadata.ExploitDifficulty))
		}
		if incident.EventMetadata.IncidentType != "" {
			sb.WriteString(fmt.Sprintf("  - 事件类型：%s\n", incident.EventMetadata.IncidentType))
		}
		sb.WriteString("\n")
	}

	if result.Category != "" {
		sb.WriteString(fmt.Sprintf("【AI分类】%s\n", result.Category))
	}
	if len(result.Tags) > 0 {
		sb.WriteString(fmt.Sprintf("【AI标签】%s\n", strings.Join(result.Tags, "、")))
	}
	sb.WriteString("\n")

	if len(result.Recommendations) > 0 {
		sb.WriteString("【处置建议】\n")
		for i, rec := range result.Recommendations {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
	}

	return sb.String()
}

// PredictTrend uses a weighted moving average algorithm to predict future trend points
// from historical data.
func PredictTrend(historical []coreContract.ChartTrendItem, predictDays int) statsContract.TrendPrediction {
	result := statsContract.TrendPrediction{
		Algorithm:  "weighted_moving_average",
		Confidence: 0.7,
	}

	// Convert historical data to TrendPoints
	for _, h := range historical {
		result.Historical = append(result.Historical, statsContract.TrendPoint{
			Date:  h.Date,
			Count: float64(h.Count),
		})
	}

	if len(historical) == 0 || predictDays <= 0 {
		return result
	}

	// Use weighted moving average with window size up to 7
	windowSize := 7
	if len(historical) < windowSize {
		windowSize = len(historical)
	}

	// Get the last windowSize items for prediction base
	recentData := historical[len(historical)-windowSize:]

	// Calculate weighted moving average
	// Weights increase linearly: 1, 2, 3, ..., windowSize
	var weightedSum float64
	var weightTotal float64
	for i, item := range recentData {
		weight := float64(i + 1)
		weightedSum += float64(item.Count) * weight
		weightTotal += weight
	}
	baseAvg := weightedSum / weightTotal

	// Calculate trend (slope) from recent data
	var trend float64
	if len(recentData) >= 2 {
		firstHalfSum := 0.0
		secondHalfSum := 0.0
		mid := len(recentData) / 2
		for i := 0; i < mid; i++ {
			firstHalfSum += float64(recentData[i].Count)
		}
		for i := mid; i < len(recentData); i++ {
			secondHalfSum += float64(recentData[i].Count)
		}
		firstAvg := firstHalfSum / float64(mid)
		secondAvg := secondHalfSum / float64(len(recentData)-mid)
		trend = (secondAvg - firstAvg) / float64(len(recentData))
	}

	// Parse last date to generate future dates
	lastDate := historical[len(historical)-1].Date
	parsedDate, err := time.Parse("2006-01-02", lastDate)
	if err != nil {
		parsedDate = time.Now()
	}

	// Generate predictions
	for i := 1; i <= predictDays; i++ {
		nextDate := parsedDate.AddDate(0, 0, i)
		predicted := baseAvg + trend*float64(i)
		if predicted < 0 {
			predicted = 0
		}
		result.Predicted = append(result.Predicted, statsContract.TrendPoint{
			Date:  nextDate.Format("2006-01-02"),
			Count: math.Round(predicted*100) / 100,
		})
	}

	// Adjust confidence based on data quality
	if len(historical) >= 30 {
		result.Confidence = 0.85
	} else if len(historical) >= 14 {
		result.Confidence = 0.75
	} else if len(historical) >= 7 {
		result.Confidence = 0.65
	} else {
		result.Confidence = 0.5
	}

	return result
}
