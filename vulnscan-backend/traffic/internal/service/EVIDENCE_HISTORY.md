# 证据模块的自动历史关联

历史关联由证据模块处理：共享适配层检索平台事件，事实引擎核验关系，R06/R07解释历史与当前模式，统一层再压缩为报告上下文。初报、终报和手动刷新共用该链路；查看或导出已有报告只读取保存版本。

## 历史输入

默认检索当前事件开始之前30天的同资产或同IOC事件，包括归档事件。审核通过、驳回、未审核都参与，查询与语义规划均不以审核状态筛选。平台事件的身份、时间与IOC是关联依据，不用旧模型概率替代活动事实。

一次查询服务全部规则和槽位。精确匹配IOC类型和值、登记资产地址；程序再核验活动时间、资产和IOC，排除当前事件、当前快照来源、别名、重复事件、后续事件及无有效时间的记录。

默认上限：32个资产地址、32个IOC、201个候选（多取一条检测截断）、最多200条处理记录、4 MiB候选上下文、10秒查询超时。仅查询必要字段，不读取旧报告、消息或报文。全部匹配记录参与统计，按同资产且同IOC、仅同IOC、仅同资产分组压缩，避免全量历史正文进入模型。

## 算法与语义

`applyPlatformHistory` 转换为 `Input.PlatformHistory`，该字段只由适配层构造，不接受JSON导入覆盖。原有 `Input.History` 的独立阶段、战役、群体及端点证明保留。

- 同资产同IOC复发：统计独立事件数和活跃日期，达到原门槛才成立。
- 同IOC基础设施持续活动：按实际日期和登记资产计算持续性，事件不重复计数。
- IOC新颖性：只在历史覆盖完整且IOC绑定明确时判断。平台地址资料不足以核验完整传输端点，不据此伪造端点新颖性。
- 阶段递进、协同参数等：保持各自CurrentStage、战役及完整成员要求，不从普通历史补造字段。
- R06 `history.activity_association`：解释关联与复发模式，引用实际历史摘要。
- R07 `history.alternative_explanation`：使用全部关联历史比较异常与正常业务解释，不要求误报审核标记，不自动认定误报。

R06/R07保留 `ExplanationOnly=true`，参与报告意义解释、替代解释和建议。复发指标由事实规则提供，语义与依赖事实不重复计证。同资产不自动等于同战役。

每个范围最多三个历史关系分组，统计包含全部匹配记录，提供代表事件引用。当前模式同时携带已成立规则指标。操作级命题不重复规划同一范围的历史任务。历史任务仍受共享语义预算限制，超预算保留原因。

## 完整性、诊断和缓存

截断或有材料未通过核验时覆盖不完整。已取得的正向复发证明仍可使用，质量为partial、指标为已检索记录下界；未达到门槛不能充当阴性，新颖性也不会据此成立。查询失败保留 `load_history` 诊断，其他事实继续执行。

`evidence_diagnostics.manifest.history` 记录候选、匹配、排除、截断和原因，例如 `history_query_failed`、`history_window_unavailable`、`history_identity_unresolved`、`history_identity_budget_exceeded`、`history_candidate_budget_exceeded`、`no_matching_platform_history`。

历史内容与版本进入事实缓存标识，语义缓存依赖事实标识；新增历史影响下一次生成，不改写旧报告。规则版本 `evidence-algorithms-0.5`，快照适配器 `snapshot-evidence-adapter-0.5`，语义版本 `evidence-semantics-0.4`，语义适配器 `snapshot-semantic-adapter-0.3`。

新增 `idx_events_history_time(last_seen_at,event_id)`，沿用创建时间索引，数据库升级时补建。真实大库建索引耗时、查询计划、此前30个生产事件和真实模型效果尚未验证。

统一输出与精华压缩见[统一证据说明](../../../evidence/NORMALIZATION.md)。
