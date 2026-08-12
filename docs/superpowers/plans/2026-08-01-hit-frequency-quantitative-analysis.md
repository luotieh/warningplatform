# 命中频次量化分析 + 新字段辅助研判 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在自动分析链路中增加命中频次量化指标（总次数/时间跨度/频率）和新增字段（session_summary/命中记录摘要/volume_role 新取值），提升 LLM 研判的准确性

**Architecture:** 仅修改 `agents.go` 中的 `formatAuxContext()` 和 `autoAnalysisPrompt()`，从 context JSON 中提取 occurrence_count/session_summary/occurrences 摘要，更新分析要求中的频次分析指导

**Tech Stack:** Go 1.x

## Global Constraints

- 所有新增区块内的字段缺失时自动跳过，不污染 prompt（emit/scalarString 返回空字符串）
- Token 预算不调整：新增约 150-300 tokens，eventDataBudgetTokens=8500 裕量充足
- occurrences 摘要最多统计 20 条（maxOccurrences=200 可能很大）
- 不涉及前端变更

---

## 文件预定义

| 文件 | 操作 | 职责 |
|------|------|------|
| `vulnscan-backend/traffic/internal/service/agents.go` | 修改 | `formatAuxContext` + `autoAnalysisPrompt` 中的分析要求段落 |

---

### Task 1: formatAuxContext — 新增命中频次量化区块

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/agents.go`

**Interfaces:**
- Consumes: `ctx["occurrence_count"]`, `ctx["first_time"]`, `ctx["last_time"]`, `ctx["last_seen_at"]`
- Produces: 命中频次量化指标文本注入 prompt

- [ ] **Step 1: 在 agents.go 中新增时间解析和频率计算辅助函数**

在 `agentWorkflowInflight` 定义之后、`RunAgentWorkflowAsync` 之前添加：

```go
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse: %s", s)
}

func freqRateFloat(count int, first, last string) float64 {
	t1, err1 := parseTime(first)
	t2, err2 := parseTime(last)
	if err1 != nil || err2 != nil || t2.Before(t1) || t2.Equal(t1) {
		return 0
	}
	hours := t2.Sub(t1).Hours()
	if hours <= 0 {
		hours = 0.001
	}
	return float64(count) / hours
}
```

在 `scalarString` 之后添加：

```go
func calcFreqRate(count int, first, last string) string {
	if count <= 1 || first == "" || last == "" {
		return ""
	}
	f := freqRateFloat(count, first, last)
	if f <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f次/小时", f)
}
```

- [ ] **Step 2: 在 formatAuxContext 中流量统计区块之后插入命中频次区块**

```go
	// 命中频次量化（全局权威频次 + 时间跨度 + 频率 + 收敛状态）
	if count, ok := ctx["occurrence_count"]; ok {
		cnt := toInt(count)
		if cnt > 0 {
			first := asString(ctx["first_time"])
			last := asString(ctx["last_time"])
			freqRate := calcFreqRate(cnt, first, last)
			isFinal := false
			if ls, ok := ctx["last_seen_at"]; ok {
				if lastSeen, err := parseTime(asString(ls)); err == nil {
					isFinal = time.Since(lastSeen) >= 10*time.Minute
				}
			}
			b.WriteString("- 命中频次量化(occurrence_count)：\n")
			emit("  ", "总计命中次数", cnt)
			if first != "" {
				emit("  ", "首次命中", first)
			}
			if last != "" {
				emit("  ", "末次命中", last)
			}
			if freqRate != "" {
				f := freqRateFloat(cnt, first, last)
				freqType := "低频"
				if cnt >= 3 && f >= 6.0 {
					freqType = "高频突发"
				} else if cnt >= 2 && f >= 1.0 {
					freqType = "中频持续"
				}
				emit("  ", "命中频率", fmt.Sprintf("%s（%s）", freqRate, freqType))
			}
			if isFinal {
				emit("  ", "收敛状态", "已收敛（最终频次已确定）")
			}
		}
	}
```

- [ ] **Step 3: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

- [ ] **Step 4: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/agents.go
git commit -m "feat: 报告中新增命中频次量化分析（总次数/时间跨度/频率/收敛状态）"
```

---

### Task 2: formatAuxContext — 新增 session_summary 区块

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/agents.go`

- [ ] **Step 1: 在命中频次区块之后插入 session_summary 区块**

```go
	// 双向会话统计（IP 对的正反向流量汇总，辅助判断数据流向）
	if ss, ok := ctx["session_summary"].(map[string]any); ok && len(ss) > 0 {
		b.WriteString("- 双向会话统计(session_summary)：\n")
		emit("  ", "会话首包(epoch)", ss["first_time_usec"])
		emit("  ", "会话末包(epoch)", ss["last_time_usec"])
		if line := joinKV(ss, []string{"client_packets", "client_wire_bytes"}, " "); line != "" {
			emit("  ", "客户端→服务端", line+"（包数, wire_bytes）")
		}
		if line := joinKV(ss, []string{"server_packets", "server_wire_bytes"}, " "); line != "" {
			emit("  ", "服务端→客户端", line+"（包数, wire_bytes）")
		}
		emit("  ", "会话内命中次数", ss["hit_count"])
	}
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/agents.go
git commit -m "feat: 报告中新增 session_summary 双向会话统计"
```

---

### Task 3: formatAuxContext — 新增命中记录摘要

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/agents.go`

- [ ] **Step 1: 在 session_summary 区块之后插入命中记录摘要区块**

```go
	// 命中记录摘要（通信模式概况：方向分布、明文载荷比例、TCP重传情况）
	if occs, ok := ctx["occurrences"].([]any); ok && len(occs) > 0 {
		const maxOccSummary = 20
		total := len(occs)
		n := total
		if n > maxOccSummary {
			n = maxOccSummary
		}
		var reqCount, respCount, plainCount, retransCount int
		for i := 0; i < n; i++ {
			if om, ok := occs[i].(map[string]any); ok {
				switch asString(om["message_direction"]) {
				case "request":
					reqCount++
				case "response":
					respCount++
				}
				if asString(om["payload_text"]) != "" {
					plainCount++
				}
				for _, key := range []string{"request", "response"} {
					if sub, ok := om[key].(map[string]any); ok {
						if v, ok := sub["retransmission"]; ok && v == true {
							retransCount++
						}
					}
				}
			}
		}
		suffix := ""
		if total > maxOccSummary {
			suffix = fmt.Sprintf("（共%d条，统计前%d条）", total, maxOccSummary)
		}
		b.WriteString("- 命中记录摘要" + suffix + "：\n")
		emit("  ", "方向分布", fmt.Sprintf("请求%d次 / 响应%d次", reqCount, respCount))
		emit("  ", "有明文载荷", fmt.Sprintf("%d条", plainCount))
		if retransCount > 0 {
			emit("  ", "TCP重传", fmt.Sprintf("%d条（网络异常或反检测特征）", retransCount))
		}
	}
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/agents.go
git commit -m "feat: 报告中新增命中记录通信模式摘要"
```

---

### Task 4: formatAuxContext — 补充 volume_role 新增取值

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/agents.go` (volume_role switch)

- [ ] **Step 1: 替换 volume_role switch 语句**

将现有 switch（仅 to_ioc/from_ioc + default）替换为：

```go
		switch asString(fs["volume_role"]) {
		case "to_ioc":
			emit("", "通联方向", "to_ioc（数据流向 IOC，疑似数据外传/上传）")
		case "from_ioc":
			emit("", "通联方向", "from_ioc（数据来自 IOC，疑似载荷下载）")
		case "client_only":
			emit("", "通联方向", "client_only（仅客户端有数据，单向通讯，可能只有请求无响应）")
		case "server_only":
			emit("", "通联方向", "server_only（仅服务端有数据，可能只有响应无请求）")
		case "upload_to_ioc":
			emit("", "通联方向", "upload_to_ioc（client_bytes≥server_bytes×10，确认数据外泄）")
		case "download_from_ioc":
			emit("", "通联方向", "download_from_ioc（server_bytes≥client_bytes×10，确认载荷投递）")
		case "bidirectional":
			emit("", "通联方向", "bidirectional（双向等量，正常交互或定期 beacon）")
		default:
			emit("", "通联方向", fs["volume_role"])
		}
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/agents.go
git commit -m "feat: volume_role 新增 5 个取值的语义说明"
```

---

### Task 5: autoAnalysisPrompt — 更新分析要求

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/agents.go`

- [ ] **Step 1: 替换分析要求段落（第 119-124 行）**

```go
		// 利用「通联方向」与双向会话统计(客户端/服务端字节比)判断外传/下载/beacon；
		// 命中频次量化分析：occurrence_count 为全局权威命中总次数。
		//   单次(1)可能为误报或偶然通讯；低频(≥2、跨度>1h)为周期性 beacon；
		//   高频突发(≥3、≤10min)为持续攻击，提高威胁置信度。
		//   local_hit_count 仅为节点近似分诊提示，与 occurrence_count 语义不同，勿重复计数。
		//   已收敛(is_final)时 occurrence_count 为最终频次；进行中可能继续增加。
		// 若事件带「建议处置(情报侧)」，需明确采纳或修正并说明理由；
		// 信息不足时写清缺口与下一步应查询的数据；不要把未执行的剧本结果写成已完成。
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/agents.go
git commit -m "feat: 更新自动分析要求 — 命中频次量化指导 + session_summary 辅助研判"
```

---

### Task 6: 集成验证

- [ ] **Step 1: 运行现有测试**

```bash
cd vulnscan-backend && go test ./traffic/... 2>&1 | tail -20
```

- [ ] **Step 2: 有调整则提交**

```bash
git add -A && git commit -m "chore: 集成后微调"
```
