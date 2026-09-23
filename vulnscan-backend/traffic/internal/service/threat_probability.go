package service

import (
	"regexp"
	"strconv"
)

// threatProbabilityPatterns 从模型研判报告文本中提取威胁概率（0-100）。
// 报告模板要求输出「威胁事件概率0–100%及依据」（见 autoAnalysisPrompt 输出格式：
// 【结论】…威胁事件概率X%%…），历史模板另有「威胁概率」「危险攻击概率」等措辞，
// 实际输出多为 “威胁事件概率85%” / “威胁事件概率：75%” / “**威胁事件概率**：80%”
// 等形态，逐个模式取首个命中。末位是不带标签的兜底：报告只使用一个概率指标，
// 标签措辞漂移时仍能取到 “概率为85%” 之类的数值。
var threatProbabilityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:威胁事件概率|威胁概率|危险攻击概率|攻击概率|研判概率)[^\d%]{0,16}?(\d{1,3}(?:\.\d+)?)\s*%`),
	regexp.MustCompile(`(?:威胁事件概率|威胁概率|危险攻击概率|攻击概率|研判概率)[^\d%]{0,16}?(\d{1,3}(?:\.\d+)?)\s*（?百分`),
	regexp.MustCompile(`概率[^\d%]{0,16}?(\d{1,3}(?:\.\d+)?)\s*%`),
}

// parseThreatProbability 返回 (概率, 是否提取成功)；概率收敛到 [0,100]。
// 提取失败返回 ok=false，调用方不得用 0 覆盖既有值——0% 与“未研判”语义不同。
// probabilityRangePattern 剥离模板范围回显（如“威胁事件概率0–100%及依据”中的
// 0–100%），避免范围上下界被误当作概率值。
var probabilityRangePattern = regexp.MustCompile(`\d{1,3}\s*[–—\-~～]\s*\d{1,3}\s*%`)

func parseThreatProbability(report string) (float64, bool) {
	report = probabilityRangePattern.ReplaceAllString(report, "")
	for _, pattern := range threatProbabilityPatterns {
		match := pattern.FindStringSubmatch(report)
		if len(match) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			continue
		}
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		return value, true
	}
	return 0, false
}
