# 安全事件分析报告模版

> 版本：v1.0
> 来源：基于 `docs/report_eg.md`《网络安全流量安全事件通报模板》整理，用于优化安全事件报告生成接口。

## 1. 模版说明

### 1.1 设计原则

- **基础信息与漏洞通报模版对齐**：`一、基础信息` 沿用现有「网络安全隐患详情」通报表的字段样式与布局，避免两份报告风格差距过大。
- **章节规则**：`一、二、四、五` 为固定章节，参考现有通报模版；`三、流量证据与IOC明细` 按数据可用性动态渲染，并作为「隐患描述/漏洞详情」的主体内容（即原报告中的漏洞详情部分）。
- **核心结论前置**：事件概述必须先给结论，再给证据，便于管理层快速决策。
- **动态隐藏**：无数据的章节自动省略；置信度、级别等字段必须附带判定依据。

### 1.2 变量约定

模版变量使用 Go template 风格 `{{.Field}}`，与报告接口 JSON 契约字段一一对应；列表型数据使用 `{{range}}` 循环渲染。字段映射见第 3 节。

## 2. 模版正文

**《网络安全安全事件分析报告》**

---

### 一、基础信息

| **字段** | **内容** |
| --- | --- |
| **通报编号** | {{.IncidentNo}}（按企业编号规则生成） |
| **事件级别** | {{.LevelEmoji}} **{{.Level}}**（判定依据：{{.LevelBasis}}） |
| **通报时间** | {{.ReportTime}}（精确至分钟） |
| **涉及系统** | {{.SystemName}}（IP范围：{{.AssetIPRange}}） |
| **通报对象** | {{.NotifyTargets}}（*根据事件级别动态调整*） |
| **事件来源** | {{.Source}} |
| **处置状态** | {{.Status}}（风险评分：{{.RiskScore}}） |
| **涉及单位** | {{.Unit}}（类型：{{.UnitType}}） |
| **所属行业** | {{.Industry}}（等保级别：{{.MLPSLevel}}） |

> 可选字段（存在时追加）：网站名称 `{{.AssetName}}`、网站域名IP `{{.DomainIP}}`、网站IP `{{.SiteIP}}`、归属地 `{{.Region}}`、数据编号 `{{.DataNo}}`、厂商上报归属地 `{{.VendorRegion}}`、隐患URL `{{.IncidentURL}}`。

---

### 二、事件概述

> **核心结论前置**：
> {{.CoreConclusion}}

**事件描述**：

{{.Description}}

---

### 三、流量证据与IOC明细

> 本章为原「隐患描述/漏洞详情」章节的扩展主体，仅在存在流量证据或IOC数据时渲染。

#### 3.1 关键流量证据（*必须提供可验证数据*）

| **证据类型** | **技术细节** | **证据来源** | **置信度** |
| --- | --- | --- | --- |
| {{range .TrafficEvidence}}**{{.Type}}** | {{.Detail}} | {{.Source}} | {{.ConfidenceText}} ({{.Confidence}}%) |
| {{end}} |

#### 3.2 IOC关联验证

| **IOC类型** | **IOC值** | **威胁情报来源** | **匹配结果** |
| --- | --- | --- | --- |
| {{range .Iocs}}**{{.Type}}** | {{.Value}} | {{.ThreatSource}} | {{.Match}} |
| {{end}} |

#### 3.3 IOC有效性说明

{{.IocValidity}}

#### 3.4 关联漏洞清单（可选）

| **漏洞标题** | **级别** | **CVE** | **状态** |
| --- | --- | --- | --- |
| {{range .Vulnerabilities}}**{{.Title}}** | {{.Severity}} | {{.CveID}} | {{.Status}} |
| {{end}} |

---

### 四、影响评估

| **维度** | **评估结果** |
| --- | --- |
| **业务影响** | {{.Impact.Business}} |
| **数据风险** | {{.Impact.DataRisk}} |
| **攻击意图** | {{.Impact.Intent}} |

---

### 五、处置建议

#### 立即行动项（*30分钟内完成*）

{{range .ImmediateActions}}
1. **{{.Action}}**：
   - {{.Detail}}
{{end}}

#### 后续处置项（*24小时内完成*）

{{range .FollowupActions}}
1. **{{.Action}}**：
   - {{.Detail}}
{{end}}

#### 整改闭环

**整改建议**：{{.RemediationPlan}}

**处置要求**：{{.RemediationAdvice}}

**责任人**：{{.Assignee}}　**完成期限**：{{.Deadline}}　**关闭说明**：{{.RemediationResult}}

---

### 六、附件清单

{{range .Attachments}}
1. [ ] **{{.Name}}**：
   - {{.Path}}
{{end}}

---

### 七、处置过程记录（可选）

| **时间** | **操作** | **操作人** | **说明** |
| --- | --- | --- | --- |
| {{range .OperationLogs}}{{.Time}} | {{.Operation}} | {{.Operator}} | {{.Comment}} |
| {{end}} |

## 3. 字段映射与接口优化建议

### 3.1 现有字段映射

以下变量已与 `IncidentReportData` 接口契约（`vulnscan-backend/incident/stats/stats-contract/contract.go`）对应，报告接口可直接取值：

| 模版变量 | 当前接口字段 | 说明 |
| --- | --- | --- |
| `{{.IncidentNo}}` | `incident_no` | 通报/隐患编号 |
| `{{.Level}}` | `level` / `warning_level` | 事件级别 |
| `{{.ReportTime}}` | `report_time` | 通报时间 |
| `{{.SystemName}}` | `system_name` | 涉及系统 |
| `{{.Source}}` | `source` | 事件来源 |
| `{{.Status}}` | `status` | 处置状态 |
| `{{.RiskScore}}` | `risk_score` | 风险评分 |
| `{{.Unit}}` / `{{.UnitType}}` | `unit` / `unit_type` | 涉及单位 |
| `{{.Industry}}` / `{{.MLPSLevel}}` | `industry` / `mlps_level` | 行业与等保 |
| `{{.Description}}` | `description` / `description_sections` | 事件描述（成因/证据/溯源） |
| `{{.RemediationPlan}}` | `remediation_plan` | 整改建议 |
| `{{.RemediationAdvice}}` | `remediation_advice` | 处置要求 |
| `{{.Assignee}}` / `{{.Deadline}}` | `remediation_assignee` / `remediation_deadline` | 责任人/期限 |
| `{{.Vulnerabilities}}` | `vulnerabilities` | 关联漏洞清单 |
| `{{.OperationLogs}}` | `operation_logs` | 处置过程记录 |

### 3.2 建议新增字段

为支持模版 `三、四、五、六` 章节，建议扩展 `IncidentReportData` 契约：

```go
// 关键流量证据
type IncidentReportTrafficEvidence struct {
    Type           string `json:"type"`            // 证据类型：异常流量模式/恶意载荷特征/数据外传痕迹
    Detail         string `json:"detail"`          // 技术细节（源IP、次数、请求特征等）
    Source         string `json:"source"`          // 证据来源（日志ID/PCAP哈希等）
    Confidence     int    `json:"confidence"`      // 置信度 0-100
    ConfidenceText string `json:"confidence_text"` // 展示文案，如 ⭐⭐⭐⭐☆
}

// IOC 关联验证
type IncidentReportIoc struct {
    Type         string `json:"type"`           // 恶意IP/恶意域名/TLS指纹
    Value        string `json:"value"`          // IOC值
    ThreatSource string `json:"threat_source"`  // 威胁情报来源
    Match        string `json:"match"`          // 匹配结果说明
}

// 影响评估
type IncidentReportImpact struct {
    Business string `json:"business"` // 业务影响
    DataRisk string `json:"data_risk"` // 数据风险
    Intent   string `json:"intent"`   // 攻击意图
}

// 处置行动项
type IncidentReportAction struct {
    Action string `json:"action"` // 行动名称：流量阻断/证据固化/漏洞修复等
    Detail string `json:"detail"` // 具体措施
}

// 附件
type IncidentReportAttachment struct {
    Name string `json:"name"` // 附件名称
    Path string `json:"path"` // 附件路径/说明
}
```

对应在 `IncidentReportData` 中增加：

```go
TrafficEvidence  []IncidentReportTrafficEvidence `json:"traffic_evidence,omitempty"`
Iocs             []IncidentReportIoc             `json:"iocs,omitempty"`
IocValidity      string                          `json:"ioc_validity,omitempty"`
Impact           IncidentReportImpact            `json:"impact,omitempty"`
ImmediateActions []IncidentReportAction          `json:"immediate_actions,omitempty"`
FollowupActions  []IncidentReportAction          `json:"followup_actions,omitempty"`
Attachments      []IncidentReportAttachment      `json:"attachments,omitempty"`
NotifyTargets    string                          `json:"notify_targets,omitempty"`
LevelEmoji       string                          `json:"level_emoji,omitempty"`
LevelBasis       string                          `json:"level_basis,omitempty"`
CoreConclusion   string                          `json:"core_conclusion,omitempty"`
AssetIPRange     string                          `json:"asset_ip_range,omitempty"`
```

### 3.3 接口优化建议

1. **新增 Markdown 渲染通道**：在 `ExportIncidentReport` 中支持 `format=md`，按本模版渲染 Markdown；PDF/DOCX 先渲染 Markdown 再转换，避免 PDF/DOCX 生成器与模版结构耦合。
2. **AI 输出结构化**：AI 分析结果按 `TrafficEvidence`、`Iocs`、`Impact`、`ImmediateActions` 等结构输出，替代自由文本，保证 `三、四、五` 章节可稳定填充。
3. **章节动态渲染**：`三、七` 及关联漏洞清单按数据是否为空自动隐藏；`一、二、四、五、六` 保持固定顺序。
4. **级别与置信度规范化**：级别统一使用 `🔴高危/🟠中危/🟡低危/🟢提示` 并附判定依据；置信度统一为百分比 + 星级文案。
5. **编号规则统一**：通报编号 `{{.IncidentNo}}` 由后端按 `SEC-ALERT-YYYYMMDD-NNN` 规则生成，模版不参与编号逻辑。
6. **证据引用可验证**：每个证据条目必须携带来源 ID（日志 ID、PCAP 哈希、规则 ID），附件路径与证据包命名保持一致。
