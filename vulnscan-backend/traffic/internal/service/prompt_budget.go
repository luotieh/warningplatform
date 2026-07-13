package service

import "math"

// truncateMarker 追加在被截断内容末尾,提示模型存在未展示数据(应归入「信息缺口」)。
const truncateMarker = "…(已截断)"

// truncateRunes 按 rune 数截断字符串(CJK 安全),超过 maxRunes 时截断并追加标记。
func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + truncateMarker
}

// LLM 上下文预算(常量,无管理端配置)。目标:本地 Qwen32B / max-model-len 16384,
// input 预算 10K、输出预留 6K。窗口由用户在推理端(vllm-ascend/MindIE)设置;
// 此处仅据此裁剪 prompt,保证 32B 输出完整报告、不被截断。
const (
	// 输出预留(max_tokens=6000)在 client.chatMaxTokens 处强制,此处不再重复定义。
	// promptBudgetTokens 是整段 prompt(system+user)的 token 上限。
	promptBudgetTokens = 10000
	// eventDataBudgetTokens 是事件数据部分(摘要+observables 等)的软上限,
	// 超出即按优先级截断;固定骨架(system+指令+模板)约占 ~1200。
	eventDataBudgetTokens = 8500

	// auxSampleMaxRunes 限制单条应用层样本(payload/请求体)长度。
	auxSampleMaxRunes = 300
	// auxNarrativeMaxRunes 限制情报告警叙述(narrative)长度。
	auxNarrativeMaxRunes = 300
	// maxObservables 限制注入 prompt 的可观察对象条数。
	maxObservables = 30
)

// estimateTokens 估算字符串的 token 数,供截断决策使用(非精确、刻意保守)。
// CJK 字符按 ~0.7 token/字,其余按 rune/3.5,整体乘 1.1 保守系数并向上取整。
// 宁可高估(提前截断)也不低估(溢出上下文窗口导致输出被挤掉)。
func estimateTokens(s string) int {
	cjk := 0
	other := 0
	for _, r := range s {
		if isCJK(r) {
			cjk++
		} else {
			other++
		}
	}
	raw := float64(cjk)*0.7 + float64(other)/3.5
	return int(math.Ceil(raw * 1.1))
}

// isCJK 判断是否为 CJK 表意文字/假名/CJK 标点/全角字符(统一 >= 0x3000)。
func isCJK(r rune) bool {
	return r >= 0x3000
}

// fitToTokenBudget 截断字符串使其估算 token 数不超过 tokenBudget。未超则原样返回。
// 单 rune 最高 token 成本为 0.77(0.7×1.1,全 CJK),据此估算起点再逐步收缩,
// 循环校验 estimateTokens 直到落入预算,保证结果一定不溢出。
func fitToTokenBudget(s string, tokenBudget int) string {
	if estimateTokens(s) <= tokenBudget {
		return s
	}
	runes := []rune(s)
	maxRunes := int(float64(tokenBudget) / 0.77)
	for maxRunes > 0 {
		cand := string(runes[:min(maxRunes, len(runes))]) + truncateMarker
		if estimateTokens(cand) <= tokenBudget {
			return cand
		}
		maxRunes -= 64
	}
	return truncateMarker
}
