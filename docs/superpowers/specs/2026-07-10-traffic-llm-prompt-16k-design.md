# 流量分析自动分析 Prompt 重构(适配 16K / Qwen32B)设计

- 日期: 2026-07-10
- 分支: trafficanalysis
- 状态: 已确认,待实现

## 1. 背景与问题

流量分析(traffic)后端的 LLM 自动分析链路
(`RunAgentWorkflow → autoAnalysisPrompt → LLMClient.Chat`)在本地部署的
**Qwen32B / 上下文 10K** 环境下输出异常。实测输出示例:

- **被截断**:报告在句子中间(如"确认是否为")戛然而止,后面直接接上系统追加的
  固定「建议」文案(`llmExpertResponse` 的 `当前结果由已配置 LLM 生成…`),确认为
  自动分析链路而非工程师对话。
- **质量差(自言自语)**:输出是"喂,我现在需要处理这个安全事件…"这种第一人称
  复述输入的碎碎念,而非要求的结构化报告。

### 根因

1. **无 `max_tokens`**:`Chat()` 真实调用未设 `max_tokens`。310P 类推理端
   `max-model-len` 是 prompt+输出**共享**的,prompt 一大输出就被挤没 → 截断。
2. **context 重复注入**:`autoAnalysisPrompt` 把同一份 `event.Context`
   塞了两遍(`formatAuxContext` 格式化版 + `原始上下文(JSON)` 原文版),白吃 token。
3. **双重人格**:`Chat()` 对所有调用方硬编码「DeepSOC 助手」system prompt,
   与 user 消息里的"你是自动分析引擎"冲突,还白占 token。
4. **指令太软**:prompt 只说"基于信息生成分析",没有硬性输出契约,32B 小模型
   遵循力弱 → 复述输入。

## 2. 硬件判断(为何目标定 16K)

硬件:4×Atlas 300I Duo(昇腾 310P,单卡 96GB LPDDR4X,共 384GB;280 INT8 TOPS /
140 FP16 TFLOPS)。

结论:**10K 不是硬件墙,而是软配置**。384GB 显存跑 32B 的 KV cache 到 16~20k
绰绰有余;社区实测 Qwen3-32B 在该卡跑 `max-model-len≈20480`,4 卡跑 30B 到 32768。

但 310P **没有压缩注意力掩码实现**:按 `[max_model_len, max_model_len]` float16 建
完整因果掩码,官方 vllm-ascend 建议手动设保守值(如 16384)、勿用 auto(会 OOM)。
窗口越大掩码显存与 prefill 计算**平方级**增长,而该卡算力一般。

**落点**:用户在 LLM 推理端把 `max-model-len` 设为 **16384**;精简 prompt 仍有价值
(prefill 平方级 → prompt 越瘦首字越快;精简指令让小模型更听话)。二者互补,都做。

参考:
- https://docs.vllm.ai/projects/ascend/en/latest/tutorials/hardwares/310p.html
- https://www.hardware-corner.net/huawei-atlas-300i-duo-96gb-llm-20250830/
- https://github.com/vllm-project/vllm-ascend/issues/1813

## 3. 决策约束(用户确认)

1. 预算目标 **16K**,Go 侧按常量写死。
2. **不加管理端/前端配置**:窗口由用户自行在 LLM 推理端调整。
3. 纳入两个新事件字段(见 §6)。
4. 保证 Qwen32B 输出**完整报告**;**一句话结论前置**以抗截断。

## 4. Token 预算(常量,无管理端配置)

```
max-model-len 16384             (用户在 vllm-ascend/MindIE 端设置)
├─ maxOutputTokens   = 6000     (Chat 新设 max_tokens)
├─ safetyMargin      ~ 400
└─ promptBudget      ≈ 9500     (system+user 全部计入)
     ├─ 固定骨架(精简 system + 指令 + 模板)  ≤ ~1200
     └─ 事件数据                              ≈ 8000  (超则截断)
```

以上为 Go 常量(如 `const maxOutputTokens = 6000`、`const promptBudgetTokens = 9500`、
`const eventDataBudgetTokens = 8000`),集中定义、便于将来手改。

### Token 估算(轻量启发式,不引入 tokenizer 依赖)

新增 `estimateTokens(s string) int`:
- CJK 字符(含中文标点)按 `~0.7 token/字`;
- 其余字符按 `len/3.5`;
- 结果乘 `1.1` 保守系数(宁可高估致早截,不可低估致溢出)。

该估算仅用于**截断决策**,不追求精确。

## 5. `Chat` 接口改造(修截断根因)

- 签名改为 `Chat(ctx, systemPrompt, userPrompt string)`(或新增 `ChatWithSystem`,
  保留旧 `Chat` 转调以减少改动面)。自动分析传**分析专用精简 system**;工程师对话
  传原**对话 system**(`chat_service.go` / `engineer_context.go` 两处调用点同步)。
- payload 新增 **`max_tokens: 6000`、`temperature: 0.2`**(低温更守模板、少发散)。
- `HealthCheck` 不变(仍 `max_tokens:4`)。

## 6. 输出模板 + 系统提示重构(修自言自语 + 结论前置)

自动分析专用 system prompt 精简为 1–2 句角色设定(去掉现有冗长 6 条),核心是**硬性
输出契约**。强制模板(**第一行必须是一句话结论**):

```
【结论】<一句话:研判定性(误报/探测/利用尝试/有效入侵) + 核心依据 + 建议动作>

## 研判结论   (展开定性与依据)
## 关键证据   (来源→目标、端口、命中情报、payload/IOC、通联方向与体量)
## 影响与风险
## 建议处置   (若事件带 recommended_action 需明确采纳/修正并说明)
## 信息缺口
```

配套硬指令(逐字进 prompt):

> 第一行必须输出以【结论】开头的一句话总结,先给结论再展开;禁止复述输入、
> 禁止第一人称思考过程、禁止输出模板外内容。

**抗截断双保险**:
1. 输出层——结论前置,后文被截也不丢核心判断。
2. 预算层——6000 输出预留 + prompt 截断,尽量让后文根本不被截。

## 7. 纳入新字段 + 截断优先级(在 `formatAuxContext`)

新字段位于 context JSON 顶层(均 `omitempty`,向后兼容):

| 字段 | 类型 | 渲染 |
|---|---|---|
| `recommended_action` | string | 摘要中「建议处置(情报侧)」一行;模板「建议处置」据此研判 |
| `ioc_evidence` | object | 新增「情报富化证据」块 |

`ioc_evidence` 子字段:`activity`(关联活动/战役)、`threat_labels`(string[] 威胁标签)、
`source`(情报来源)、`cross_check`(交叉验证,可空)、`confidence`(置信度)、
`tlp`(TLP 等级)、`misp_event_id`(MISP 事件 id)、`narrative`(中文告警叙述,可空)。

### 截断优先级(事件数据超 `eventDataBudgetTokens` 时,从低到高砍)

1. **一句话结论所需的基础字段**(EventID/名称/严重级别/来源/描述)—— 永远保留(小)。
2. **情报富化 `ioc_evidence` + `recommended_action`** —— 高价值保留;仅 `narrative`
   超长时截到 ~300 字。
3. **应用层证据 `app`** —— 保留;`http_body_sample` / `payload_sample` 各截到 ~300 字。
4. **observables** —— 上限 ~30 条,超出计数省略。
5. **原始 context JSON** —— **从自动分析 prompt 直接删除**(摘要已覆盖,即"塞两遍"
   的那份),省下约一半 token。

被截断处统一加中文省略标记(如 `…(已截断)`),让模型知晓存在未展示数据 → 归入
「信息缺口」。

## 8. 范围

**主改**
- `internal/service/agents.go`:`autoAnalysisPrompt`(改模板+删原始 JSON)、
  `formatAuxContext`(纳入新字段)、新增 `estimateTokens` 与截断逻辑、
  自动分析 system prompt 常量。
- `internal/client/llm.go`:`Chat` 签名 + `max_tokens` / `temperature`。
- `internal/service/agents.go:63` 调用点适配新签名。

**顺带**
- 工程师对话 `engineerEventPrompt`(`chat_service.go` 与 `internal/httpapi/engineer_context.go`
  两份重复实现)的五段 JSON dump 套同一截断 helper,防其撑爆;调用点适配 `Chat` 新签名。

**不碰**
- 管理端 / 前端 / config.toml / env(不加任何新配置项)。
- `HealthCheck`、其它 `internal/client/` 数据源集成。

## 9. 测试策略

- **`estimateTokens`**:中文/英文/混合样本的单测,断言在保守区间(宁高勿低)。
- **截断逻辑**:构造超预算的 `event.Context`(超长 `payload_sample` / 大量 observables /
  大 `ioc_evidence.narrative`),断言:输出总估算 token ≤ `eventDataBudgetTokens`;
  基础字段与 `ioc_evidence` 关键项保留;原始 JSON 不出现;含截断标记。
- **`formatAuxContext` 新字段**:带 `recommended_action` / `ioc_evidence` 的样本,
  断言渲染出「情报富化证据」块及各子字段;字段缺失时不产生空行/"无"块。
- **`autoAnalysisPrompt` 结构**:断言 prompt 含模板标题与硬指令、不含"原始上下文(JSON)"、
  整体估算 token ≤ `promptBudget`。
- **手动验证**:对着 16K 的 Qwen32B 端跑一条真实事件,确认输出以【结论】开头、
  五分节完整、无中途截断。

## 10. 向后兼容

- 新字段 `omitempty`,旧事件(无 `recommended_action` / `ioc_evidence`)不受影响,
  对应摘要块不渲染。
- `Chat` 若采用「新增 `ChatWithSystem` + 旧 `Chat` 转调」方案,其它既有调用方零改动。
