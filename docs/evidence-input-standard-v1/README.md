# 标准算法输入合同：从59F＋23S的数据需求重新设计

状态：**可校验设计稿，尚未接入正式后端**。版本 `evidence-input-1.0.0`。

本次先确定算法需要什么，再确定采集和适配器如何供应。旧 `PreparedEvidenceBundle` 是服务内部执行容器，不作为新标准的字段边界。新合同独立于数据库、报告入口、Go服务结构和模型接口；JSON可直接构造、保存、复用及离线校验。

## 交付与阅读顺序

1. `input.schema.json`：严格JSON Schema，27类数据的类型、空值与公共结构。
2. `rule-requirements.json` / `.csv`：逐条59F＋23S所需字段、关联条件、基线指标、参数名及现行算法依据。
3. `data-dictionary.json`：数据族载荷和公共元信息字段定义。
4. `example-http.json`、`example-dns.json`、`example-transfer.json`：完整可校验受控输入，不含算法判定或真实阳性声明。
5. `migration-map.md`：旧输入到新标准的映射及供应缺口。
6. `validate.py`、`test_contract.py`、`verification.json`：离线格式、引用及关键一致性检查。

## 顶层结构

```text
EvidenceInput
├── schema_version / bundle_id / producer / created_at
├── event                         当前事件定位，不包含风险结论
├── snapshots[]                   每份快照的version、水位、修订水位和冻结时间
├── sources[]                     原记录位置、主键、版本、可选哈希
├── windows[]                     明确起止、时区，统一[start,end)
├── scopes[]                      真实asset_id、device_id、远端IP/端口/传输协议
├── indicators[]                  上游IOC及标签，不重复审核可信度和有效期
├── coverage[]                    各族/范围/窗口/IOC/统计总体的覆盖状态
├── artifacts[]                   原文或原始字节、编码、哈希、可见性、完整性
├── relations[]                   DNS→连接、请求→响应、重定向等可核验关系
├── datasets                      固定27个具名数组，不能替换为自由payload
└── diagnostics[]                 缺材料、冲突、预算不足等输入诊断
```

每条数据统一为 `{"meta": {...}, "data": {...}}`。`meta`包含记录ID、scope/window/coverage引用、IOC引用、来源ID、生产器版本、核验状态、缺字段及字段级来源；`data`由该族的严格类型定义，不允许任意扩展键。

`null`表示未知或不可取得；`0`是实测零；`[]`是当前输入未提供记录。空数组必须结合coverage判断是已确认零条、未取得还是协议不适用。不得用一个verified布尔值代替真实关联证明。

## 数据族按证据需求划分

| 需要表达的事实 | datasets字段 | 主要用途 |
|---|---|---|
| 命中及原始IOC位置 | alert_matches、ioc_bindings | 命中溯源、字段类型和值、资产设备与真实远端关系 |
| 独立联系、连接及会话 | contacts、connections、sessions | 时间统计、重试、会话持续和真实上下行流量 |
| DNS事务 | dns_transactions | 原始问题、响应码、答案、可注册域及其PSL版本 |
| HTTP事务 | http_transactions | 完整请求、真实事务ID、Host/Path、请求体、响应配对及重定向 |
| TLS握手 | tls_handshakes | SNI、证书、验证结果、指纹；不推测加密HTTP内容 |
| 历史与群组 | history_events、group_memberships | 精确复发、历史裁决、独立资产身份与群组关系 |
| 业务和统计参照 | authorizations、business_schedules、baselines | 授权范围、业务时间、带总体定义与单位的版本化基线 |
| 各类参照库 | brand_references、service_references、infrastructure_references、tls_references、lexical_references、domain_patterns | 品牌、服务、基础设施、信任根、词法与域名模式 |
| 独立来源 | rule_origins、intel_origins | 同源去重、上游类型标签来源 |
| 语义可读材料 | decode_chains、semantic_materials | 精确原字段、字节切片、多步解码与命题来源 |
| 内容及分块供应 | content_classifications、transfer_chunks、transfer_links | S07分类证据、S08跨事务序号/字节数/传输关联 |
| 有权确认的关系证明 | stage_campaign_proofs | 历史阶段、活动及协同参数，不能由模型臆造 |

字段完整定义见Schema和字典；这27族是可组合结构，不要求每个事件都有27族有效数据。

## 样本单位和关系约束

* `alert_matches`仅表示规则命中，同一通信可以命中多条规则。
* `contacts`仅表示已核验的独立TCP连接、DNS事务或HTTP事务，必须引用对应类型的原记录。独立去重键与被合并来源保留，报文条数不能替代联系次数。
* 时间算法按同资产、设备、端点、IOC及联系种类构建时间序列。TCP与DNS、不同IOC不能合并。
* HTTP重复以真实请求事务为单位；完整性声明针对可确定HTTP请求的总体，不能把ACK、TLS等加入HTTP请求分母。无法判断是否HTTP的记录必须进入coverage诊断，不可默默排除。
* HTTP正文有独立artifact、字节长度及request绑定。S07分类需分类器版本及可定位片段；S08需独立事务、不同序号、实际字节量和可核验join依据，相同远端IP不足以证明同一次传输。
* DNS解码保存原始问题字段、UTF-8字节区间和每步输入/输出artifact；解码后文本始终可回溯原问题。协议不适用、仅有TLS密文时不得填充HTTP/DNS语义内容。
* IOC绑定保存原记录、字段路径、原值与类型、资产/设备/远端关系。上游负责情报可信度与审核，本层不加入可信度、有效期或审批阻断。

## 完整性合同

`coverage`粒度为family＋scope＋window＋indicator＋population＋selection。同一数据族可以有多条coverage，分别声明问题、响应、历史窗口或不同来源总体。记录通过coverage_ref指向唯一一条。

* `population_completeness`：声明窗口和筛选总体的记录是否收齐。
* `content_completeness`：这些记录所需内容是否完整。
* `expected_records/loaded_records/excluded_records/duplicate_records`：数量核对；已知总数时，完整总体必须守恒。
* `denominator_description`：统计对象和排除依据；完全性不能只由“读取没有报错”推出。
* `source_snapshot_refs`：覆盖哪些固定版本和水位，跨快照不能只记录最新版本。
* `missing_fields/reason_codes`：具体缺项，不通过全局Complete掩盖局部缺口。

`population_completeness=complete`可以与`content_completeness=partial`同时成立。例如DNS问题全部取得，但响应未保存。算法需要响应码时缺材料，单纯问题标签算法仍可能有合格输入。各规则按实际必需字段与总体判断，不以整包一项缺失阻断所有规则。

运行时必须区分三类输出：有充分局部证据的规则可按既有门槛产生partial阳性；完整适用输入执行未达阈值输出not_observed；窗口、分母或关键字段缺失输出missing。输入校验器只检查合同一致性，不签发这些算法结果。

## 82项覆盖的含义

需求表逐条列出59F及23S，所有引用字段路径均经过Schema解析验证。表中required_inputs表示规则涉及的输入族与字段集合，**不是一律AND的可执行准入表达式**；可选分支和条件取决于special_condition及现行算法门槛。需要任何二选一材料的规则，不能因为另一分支为空而阻断。后续适配器迁移须把这些条件落实为规则级输入检查。

F阈值、窗口长度、最少样本数和语义前置条件保留现有算法定义；本合同不降低门槛，不把模型估计当作概率。59F和23S全有字段落点，表示标准设计覆盖需求，不代表180已供应所有数据或82项已可执行。

F输出、模型判定、风险分、联合C结果和报告均不属于L2事实输入。需要当前F命中的S槽位在运行时接收F依赖；F_IOC_TYPE_CORROB需要后置确定性类型评分依赖，也不允许预处理伪造hard_type_scores。参数与算法版本作为执行上下文另行传入，不能混入原始观测。

## 校验和复现

依赖Python和jsonschema 4.19或兼容版本，无数据库、SSH或模型调用。

```powershell
python docs/evidence-input-standard-v1/build_standard.py
python docs/evidence-input-standard-v1/build_requirements.py
python docs/evidence-input-standard-v1/build_examples.py
python docs/evidence-input-standard-v1/test_contract.py
python docs/evidence-input-standard-v1/validate.py docs/evidence-input-standard-v1/example-http.json docs/evidence-input-standard-v1/example-dns.json docs/evidence-input-standard-v1/example-transfer.json
```

Schema验证字段形状；validate.py进一步检查引用、覆盖数量、IOC原值与资产绑定、独立联系单位、artifact哈希、DNS字节切片及解码输出、HTTP分类片段和分块事务关系。它仍无法仅凭JSON判断生产器声明的源身份或join依据是否真实，生产适配器必须从原始材料核验；因此本阶段属于可复现的设计验证，不能替代真实链路验收。

## 后续接入边界

下一阶段应围绕本合同修改L1/L2供应器，再建立标准输入→原F/S执行器的适配层，最后替换正式报告入口和缓存键。当前不改算法阈值、不迁移后端、不触碰180或重新抓数据。已有工作区修改保留。
