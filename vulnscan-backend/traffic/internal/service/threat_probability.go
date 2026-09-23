package service

import (
	"regexp"
	"strconv"
)

// threatProbabilityPatterns 从模型研判报告文本中提取威胁概率（0-100）。
// 报告模板要求输出「威胁概率0–100%及计算依据」，system prompt 要求
// 「危险攻击概率（0–100%）」，实际输出多为 “威胁概率：75%” / “威胁概率约 75%” /
// “**威胁概率**：80%” / “危险攻击概率 60%” 等形态，逐个模式取首个命中。
var threatProbabilityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:威胁概率|危险攻击概率|攻击概率|研判概率)[^\d%]{0,16}?(\d{1,3}(?:\.\d+)?)\s*%`),
	regexp.MustCompile(`(?:威胁概率|危险攻击概率|攻击概率|研判概率)[^\d%]{0,16}?(\d{1,3}(?:\.\d+)?)\s*（?百分`),
}

// parseThreatProbability 返回 (概率, 是否提取成功)；概率收敛到 [0,100]。
// 提取失败返回 ok=false，调用方不得用 0 覆盖既有值——0% 与“未研判”语义不同。
func parseThreatProbability(report string) (float64, bool) {
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
