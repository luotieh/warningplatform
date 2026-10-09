# 后端证据模块

对应证据库v0.1的59项事实规则；后端计算规则版本为evidence-algorithms-0.4。已在原有两条算法基础上实现剩余57项，全部提供实际计算分支，不使用统一返回missing的占位实现。逐项列表见[RULES.md](RULES.md)。

## 模块边界

事实Engine只做确定性证据计算、数据前提检查和按需执行。输入由调用方提供，结果包含事实状态、指标、参数、快照版本、来源和依赖版本。事实计算不访问数据库、配置文件、消息队列、HTTP或LLM，不输出总体分数、威胁概率或自动取消其他证据。

新增独立SemanticEngine实现23个语义槽位（18个行为解释、5个解释专用），规则版本evidence-semantics-0.1；通过注入的模型接口按需解释事实及脱敏片段。前提检查、单批预算、事务与解码核验、引用和强度校验、失败降级及同命题去重均已实现。逐项矩阵、可信输入契约及调用示例见[SEMANTICS.md](SEMANTICS.md)。事实与语义使用独立请求及结果，模型失败不会覆盖事实结果。

仅依赖Go标准库与项目已有的golang.org/x/net中的IDNA/PSL能力，没有新增go.mod依赖。历史查询、基线生成、资产归属、授权记录获取和报告上下文压缩属于适配层；当前实现不会自行补造这些数据。

### 真实快照接入进度

报告服务已新增真实快照适配器：复用已发布快照的版本和水位，分页读取Store中的命中并批量读取修订，构建本模块Request；初报、终报和手动刷新检查全部59项，材料不足保留原因。所有算法共享输入，结果按快照、规则、参数、资产清单及独立补充输入内容缓存，报告仅接收有预算限制的事实摘要。直接调用Engine时nil Facts仍只选原有两项。

0.4新增资产级AssetInputs，把已经核验的同资产/同设备命中跨端点汇总，供端口序列、DNS与连接关联等7项资产规则使用；周期性仍按原端点计算，避免拼接不同目的形成假周期。FactInputs及SemanticInputContracts提供59项/23槽位的输入需求清单，实际就绪判断仍以规则和语义resolver为准。排错接口、补充来源契约和未覆盖项见[输入覆盖说明](../traffic/internal/service/EVIDENCE_INPUT_COVERAGE.md)。

适配器0.3新增可信来源登记及审核版本留存，在报告共用流程中自动匹配范围/时间并生产补充输入；来源变化使缓存失效，失败保留诊断并重试。另有只读真实事件验收入口，输出59项覆盖、缺口原因和集中读取耗时。来源导入、历史时间边界、正常基线训练约束及本机真实库验收限制见[可信来源与验收](../traffic/internal/service/EVIDENCE_SOURCES.md)。

基础HTTP/DNS/网络元数据可从保存记录构建；正文样本、累计流量和客户端自报标记不会升级为完整或独立核验依据。历史、基线、群体、授权及23类语义材料尚未全面接入。详见[真实数据输入与查询边界](../traffic/internal/service/EVIDENCE_INPUT.md)。当前测试覆盖服务摄入、Store读取和实际报告调用入口；生产告警与真实模型效果仍需环境验收。

| 文件领域 | 规则数 | 计算内容 |
| --- | --- | --- |
| temporal.go / temporal_rules.go | 6 | 周期、抖动、固定日窗口、跨日、突发、精确趋势检验 |
| dns_rules.go | 5 | 编码链、域名词形与语料比较、查询分布、失败率、解析到外联关联 |
| http_rules.go | 13 | 端点重复、编码、UA/体量基线、URL/品牌/凭据结构、表单和重定向链、长低量会话 |
| network_rules.go | 10 | 协议端口、稀有度、扇出、端口序列、小包、失败率、独立佐证 |
| tls_rules.go | 3 | SNI/证书名、证书链及有效期、客户端指纹矛盾 |
| group_rules.go | 10 | 核验成员、共享域与端点、协同相位、目标重叠或分工、传播链与跨日模式 |
| history_rules.go | 12 | 首现、复发、连续日、历史作息、定谳阶段、参数匹配、演练及授权活动 |

catalog.go维护只读的59项目录；types.go和inputs.go定义契约；engine.go调度；statistics.go与rule_helpers.go复用统计和前提检查。算法分域组织，适配层无需引用算法内部类型或traffic领域对象。Engine构造后不变，可复用及并发调用；调用期间不得修改输入。

## 调用与按需执行

```go
cfg := evidence.DefaultConfig()
cfg.Policies = map[evidence.FactID]map[string]float64{
    "F_RATE_RAMP": {"window_seconds": 300},
}
engine, err := evidence.NewEngine(cfg)
if err != nil { return err }
result, err := engine.Evaluate(ctx, evidence.Request{
    EventID: eventID,
    SnapshotVersion: snapshotVersion,
    Hits: verifiedHits,
    Quality: verifiedQuality,
    Facts: []evidence.FactID{"F_RATE_RAMP", evidence.MultiDayPersist},
    Inputs: scopedInputs,
    Groups: verifiedGroups,
})
```

Facts=nil保留周期性和跨日活跃两个默认选项，避免升级后自动运行全部59项。显式空slice不执行算法。其他规则须指定ID；SupportedFacts()返回59项，只有调用方明确全选时才全量执行。未知或重复事实请求返回错误。

普通规则按asset_id/endpoint_id/device_id隔离，Input.Scope须精确绑定某个命中scope且不能重复。群体规则按GroupInput单独执行，不把所有事件资产自动拼成一个群体。没有群体资料时返回unresolved_binding。群体成员必须有已核验身份、原始hit_id及共同窗口，外部记录归属须能对应成员。每组窗口为半开区间。

## 输入可信度

- event_id非空、snapshot_version为正、hits非空，hit_id唯一，scope三项身份齐全；time.Time零值、nil包数表示缺失。
- Quality声明当前命中范围是否完整，截断未知不能按未截断处理。周期和时间分布统计需要完整覆盖。
- 外部DNS/HTTP/网络/TLS/历史等使用Provenance：Verified、Complete、Version及SourceIDs。Verified由可信适配层核验设置，禁止直接采信流量正文、LLM输出或客户端自报标记。
- 输入是实际解析记录、样本、历史事件或核验资料，不是调用方预先给出的observed结论。模块计算指标、阈值比较、集合与链路关系。
- 百分位规则依赖作用范围匹配的真实基线，调用方提供指标分位数/频率表及版本来源；不使用默认p95/p99或虚构均值。历史也不从当前快照推造。
- 请求须由同一固定快照适配，相关解析记录须预先限定在声明窗口及scope。不要使用6000字符的模型摘要做统计。算法只描述已接受命中及明确提供的外部数据，不声称全网络覆盖。

## 未定阈值与算法约束

已知固定阈值按原定义实现。未明确阈值通过Config.Policies注入，缺少时返回missing_policy；未知配置键、非有限数值或非法范围在构造时拒绝。数值例子仅是配置形式，不能据合成夹具确定生产阈值。

| 规则 | 配置及含义 |
| --- | --- |
| 抖动周期 | ljung_box_lags：Ljung-Box检验滞后数；median_relative_tolerance：两半窗口中位数相对变化容限 |
| 趋势 | window_seconds：固定等长窗秒数 |
| 失败转活跃 | min_failures：至少两次的前置失败次数 |
| 品牌仿冒 | max_edit_distance：审核品牌域的最大编辑距离；已核验品牌声明也可用于授权域差异核验 |
| 非单调端口序列 | difference_entropy_threshold：端口差分熵阈值，仅提供伪随机候选线索 |
| 小包 | small_payload_bytes：单个观测payload长度上限 |
| 多资产IOC | cluster_window_seconds：时间聚集跨度上限 |
| 群体分布 | subnet_entropy_min：跨子网分布熵下限，排除全为管理/扫描角色的模式 |
| 时间协同 | bucket_seconds：等长计数窗；max_lag_bins可选，默认0，仅按配置容许相位偏移 |
| 扫描分工 | handoff_seconds：相邻连续IPv4目标段的时间衔接容限 |
| 传播链 | chain_window_seconds：同端点回连→内网访问→另一资产回连的最大时间跨度 |
| 跨日协同 | bucket_seconds：日内计数窗；每个有效日先验证群体协同，再比较不同日聚合模式 |
| 历史作息 | kl_threshold：24小时分布的KL散度阈值；零概率导致的发散单独标注，避免输出Infinity |
| 历史参数 | parameter_relative_tolerance：已定谳参数相对差异容限 |

精确Mann-Kendall只用于至少5个、至多128个无并列值的完整等长窗口，不静默改用渐近检验。当前抖动检验使用总体CV、Ljung-Box卡方尾概率与ACF峰值，不保证对任意采样过程都具有相同统计效力。日窗口用圆周滑动计数；时间处理按scope惰性复用。

URL使用IDNA及PSL，视觉混淆使用明确的有限映射，不宣称覆盖所有Unicode字符。跨注册域跳转必须有核验的事务/session及响应Location对应关系。凭据判断只检查脱敏字段结构，不把敏感值写入Finding。

TLS证书可以使用已核验的握手元数据；有DER及显式信任根时模块直接用x509验证，不联网获取证书或隐式替换信任源。指纹和CDN例外须来自已核验清单。

群体命名模式可提供经过审核的正则模板；未经核验或多模板歧义返回不足。目标分工检查连续IPv4段与时间衔接，不用无关联记录补链。

历史事件排除当前事件、重复ID和查询时间之后的资料。历史定谳仅接受人工、主机证据或权威外部来源；AI历史不能充当定谳。跨周群体复发须核验当前成员，基础设施连续活跃按相邻自然日计算。授权活动同时匹配资产、scope、时间、目标地址/网段、端口及实际解析协议，登记角色本身不构成排除证据。

0.3收紧了历史阶段递进和协同参数关联：阶段必须具有当前CurrentStage来源证明，并绑定同IOC或独立核验战役，当前阶段须高于最近历史阶段；参数比较须同时绑定真实基础设施、核验战役及资产/完整群体范围，群体成员集合必须相同。缺少证明返回missing，不从参数相似反推同战役。新增字段和边界见[HISTORY.md](HISTORY.md)。

IOC类型佐证需要调用方提供已核验的同轮hard_type_scores；模块仅核验集中度、差额和标签一致性，不自行重建旧版评分引擎，不把分数作为概率。

## 基线字段约定

Baseline以fact_id绑定当前Input.Scope或GroupInput；Verified和Complete须为true，Version及SourceIDs非空。基线的取样、角色/服务分组、最小样本量和排除当前事件由可信适配层核验。本模块校验数值有限、非负及比例范围，不负责生成外部基线。

| fact_id | Metrics键 | 额外资料 |
| --- | --- | --- |
| F_RATE_BURST | mean_per_5m、burst_ratio_p99 | 固定5分钟完整窗口 |
| F_DNS_HIGH_ENTROPY | unique_subdomain_ratio_p95、label_length_p95、query_rate_p95 | 同一注册域、窗口秒数 |
| F_DGA_LEXICAL | bigram_log_probability_p05、vowel_ratio_p05/p95、length_p05/p95 | 审核语料的BigramLogProbabilities |
| F_NXDOMAIN_CLUSTER | nxdomain_rate_p99 | 已知rcode及完整查询分母 |
| F_HTTP_FIELD_ENCODING | encoded_field_ratio_p95、encoded_field_length_p95 | 可解析完整字段 |
| F_HTTP_UA_RARITY | ua_frequency、ua_frequency_p01 | 频率必须对应实际UA和当前资产基线 |
| F_HTTP_SIZE_STABILITY | size_cv_p05、unique_size_ratio_p05 | ≥12个真实体量样本 |
| F_RARE_PORT | port_frequency_p01 | Frequencies以十进制端口字符串为键 |
| F_INFRA_RARITY | infra_frequency_p01 | Frequencies以ASN\|Country\|Reputation为键 |
| F_FANOUT_SINGLE_SRC | unique_targets_per_hour_p99 | 完整小时窗口及真实连接集合 |
| F_CONN_FAIL_RATE | connection_failure_rate_p95 | 明确TCP状态与完整连接分母 |
| F_GROUP_NXDOMAIN_CLUSTER | group_nxdomain_rate_p99 | 核验群体和DNS归属 |
| F_SHARED_DOMAIN_CLUSTER | domain_frequency_p01 | Frequencies以实际注册域为键；命名模式须审核 |
| F_SHARED_ENDPOINT | endpoint_frequency、endpoint_frequency_p01 | 频率必须对应实际端点 |
| F_HIST_MULTI_IOC_SIEGE | distinct_ioc_families_p99 | 核验历史事件及资产角色基线 |
## 输出与状态

Finding包含规则/快照版本、scope、窗口、status、eligibility、quality、指标、实际政策参数、source_ids、依赖版本、reason_code和限制。资料不足为missing/ineligible；数据充分而条件不满足为not_observed；条件成立为observed，但不能自动扩写成攻击成立。

execution_plan与事实判定独立。例如覆盖不足的跨日测量已运行，却仍不能给出阴性结论；未请求、缺字段、缺基线、缺政策或未核验绑定都有明确原因。完整结果应本地持久化，再由报告适配层生成有预算的LLM摘要。

## 验证及未完成部分

```powershell
go test ./evidence -count=1
go vet ./evidence
go test ./traffic/internal/service ./traffic/internal/client -count=1
```

事实规则阶段有27组顶层测试、281个包含子测试的测试项，59项均有成立和不成立用例，新增57项有缺少依据的降级用例。加入语义及历史关联收紧后，当前模块共53组顶层测试、557个包含子测试的测试项通过，语句覆盖率88.9%；覆盖23槽位的适用/缺失/伪造引用、预算、JSON、强度、事务、解码、历史、群体、并发及去重边界。流量service/client及traffic包回归通过，客户端另有输出token和截断HTTP契约测试。所有夹具为合成数据，不代表实战准确率。

-race未执行，当前环境缺少CGO及C编译器。尚未完成生产快照/基线/历史等适配、报告流程接入、结果落库、跨报告缓存和真实告警验收。语义模块的调用预算与23槽位已实现，生产tokenizer和真实模型验收仍待适配；现有报告流程尚未自动调用它们。
