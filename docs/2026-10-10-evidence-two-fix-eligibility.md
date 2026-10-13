# 两项修复前后：证据可完成性依赖核对

范围：2026-10-10已归档的7条真实事件固定快照、141条命中材料。按规则类型去重，只要至少一个适用事件能完成就计为一种；不代表每个事件都能执行该规则，也不代表平台所有协议和历史窗口。

修复边界：①充分提取现有基础事实；②拆开报文、消息、会话和时间序列的质量门槛。保持现有生产参数，不补正常基线、不引入外部目录、不加入历史查询、不调整模型预算。当前工作区未部署的历史实现不算现场既有材料。

完成标准：事实规则必须达到eligible且status为observed或not_observed。返回missing、缺参数、缺样本或不适用不算完成。语义输入满足与模型实际成功分开统计。

| 统计项 | 修复前 | 两项修复后 |
|---|---:|---:|
| 可完成事实规则类型 | 1 | 3 |
| 输入满足的语义槽位类型 | 2 | 2 |
| 两者合计（依赖满足，不等于LLM成功） | 3 | 5 |
| 已记录实际成功的语义槽位类型 | 1 | 尚未执行修复后模型调用 |

事实完成类型：原有F_DNS_ENCODED_LABEL；新增F_BEACON_PERIODIC和F_MULTI_DAY_PERSIST。修复前DNS规则在两条事件中已有not_observed结果；不是零。语义输入满足的是S12/dga_lexical及S15，实际成功保存过的仅S15；S12有模型失败/超时。

时间依赖核验：使用归档的真实hit_id、时间、packets和原有端点作用域，通过默认参数执行两项时间规则的离线门槛推演。仅这两项规则使用已有API质量标记作为“时间序列范围已核验”的替代开关；这不证明报文完整，也没有向数据库/报告写入该标记。两项时间规则均得到not_observed，不产生恶意命中。正式实现仍需独立时间质量字段。

端口序列：12端口事件按已保存时间顺序为22、445、3306、139、23、3389、21、27017、6379、8080、25、443，不是单调序列，因此进入差分熵分支，而生产缺difference_entropy_threshold。不能将其计为已完成。

默认Config仅提供严格周期和跨日参数。Policies为空，且现场supplemental/source登记为空；测试内配置不属于生产参数。

## 59项事实规则逐项核对

| 规则 | 名称 | 修复前 | 修复后 | 剩余条件/结论 |
|---|---|---|---|---|
| F_BEACON_PERIODIC | 严格周期信标 | 不能完成 | 可完成 | 恢复时间序列质量门槛后，4个端点作用域达到样本数并完成计算；其余仍缺样本。 |
| F_BEACON_JITTER | 抖动周期信标 | 不能完成 | 不能完成 | 生产无所需策略参数；部分规则另受样本/窗口限制。 |
| F_FIXED_DAILY_WINDOW | 每天固定时间点 | 不能完成 | 不能完成 | 全部当前事件为单日短窗口，未满足至少3个活跃日。 |
| F_MULTI_DAY_PERSIST | 跨日持续 | 不能完成 | 可完成 | 在完整读取的当前告警快照范围内完成；各作用域均只观察到1个活跃日，不能排除快照以外活跃。 |
| F_RATE_BURST | 命中突发 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_RATE_RAMP | 速率阶梯上升 | 不能完成 | 不能完成 | 生产无所需策略参数；部分规则另受样本/窗口限制。 |
| F_DNS_HIGH_ENTROPY | 长标签高基数子域（单资产） | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_DNS_ENCODED_LABEL | 子域编码结构 | 可完成 | 可完成 | 两条DNS事件已完成，均未发现编码结构；不要求恶意命中。 |
| F_DGA_LEXICAL | 词形随机性（单资产） | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_NXDOMAIN_CLUSTER | NXDOMAIN 聚集（scope=asset，单资产） | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_GROUP_NXDOMAIN_CLUSTER | 群体 NXDOMAIN 聚集（scope=asset_group） | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_FAILED_TO_ACTIVE | 失败域→激活连接 | 不能完成 | 不能完成 | 无失败前序；生产也未提供min_failures，不能把成功DNS后连接写成失败域激活。 |
| F_SHARED_DOMAIN_CLUSTER | 群体共同域名簇 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_HTTP_ENDPOINT_REPEAT | 端点重复回连 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_HTTP_FIELD_ENCODING | 字段编码异常 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_HTTP_UA_RARITY | UA 稀有/不一致 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_HTTP_SIZE_STABILITY | 请求/响应尺寸稳定 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_LONG_LOW_SESSION | 长会话低频小流量 | 不能完成 | 不能完成 | 缺完整、已核验会话及长会话条件。 |
| F_URL_ODD_AUTHORITY | URL 授权部分异常（弱欺骗） | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_URL_HOMOGLYPH | 同形混淆字符（强欺骗） | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_URL_BRAND_SUBDOMAIN_TRICK | 伪装子域（强欺骗） | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_BRAND_IMPOSTOR | 品牌仿冒 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_CRED_POST_STRUCTURE | 登录提交结构 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_FORM_CROSSSITE | 表单跨站提交 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_REDIRECT_CHAIN | 落地页→异站提交链 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_MULTI_REDIRECT_CHAIN | 多重短链跳转 | 不能完成 | 不能完成 | 缺可核验应用明文/HTTP字段；采样密文不能代替。 |
| F_PROTOCOL_PORT_MISMATCH | 协议-端口错配 | 不能完成 | 不能完成 | 缺真实服务目录，不能仅凭常见端口判协议错配。 |
| F_RARE_PORT | 稀有端口 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_DST_NOVELTY | 目的端点新颖 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_INFRA_RARITY | 目标基础设施稀有度 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_FANOUT_SINGLE_SRC | 单源目标扇出 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_PORT_SEQUENCE | 端口序列形态 | 不能完成 | 不能完成 | 生产无所需策略参数；部分规则另受样本/窗口限制。 |
| F_SMALL_PACKET | 小包无载荷 | 不能完成 | 不能完成 | 生产无所需策略参数；部分规则另受样本/窗口限制。 |
| F_CONN_FAIL_RATE | 连接失败率 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_INDEPENDENT_RULE_CORROB | 独立规则交叉佐证 | 不能完成 | 不能完成 | 缺独立来源链或已核验类型硬分；来源标签不等于独立性。 |
| F_INDEPENDENT_INTEL_CORROB | 跨情报源独立命中 | 不能完成 | 不能完成 | 缺独立来源链或已核验类型硬分；来源标签不等于独立性。 |
| F_IOC_TYPE_CORROB | IOC 类型与行为证据一致 | 不能完成 | 不能完成 | 缺独立来源链或已核验类型硬分；来源标签不等于独立性。 |
| F_TLS_SNI_MISMATCH | SNI 与目的不符 | 不能完成 | 不能完成 | 缺完整TLS材料及信任/指纹目录。 |
| F_TLS_CERT_ANOMALY | 自签名/异常证书 | 不能完成 | 不能完成 | 缺完整TLS材料及信任/指纹目录。 |
| F_TLS_JA_MISMATCH | JA3/JA4 指纹与声明不符 | 不能完成 | 不能完成 | 缺完整TLS材料及信任/指纹目录。 |
| F_MULTI_ASSET_IOC | 多资产同 IOC | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_MULTI_ASSET_DIST | 聚集分布形态 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_TIME_COORDINATION | 多资产时间协同 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_COORD_FANOUT | 协同扫描/扇出 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_INFECTION_CHAIN | 感染链传播 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_SHARED_ENDPOINT | 共享目的端点 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_FIRST_VISIT_CLUSTER | 首访时间聚集 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_COORD_PATTERN_RECURRENCE | 协同模式跨日重复 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_HIST_ASSET_IOC_RECURRENCE | 同 IOC→同资产跨日复发 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_HIST_GROUP_RECURRENCE | 群体+基础设施复发 | 不能完成 | 不能完成 | 缺多资产、完整成员或群体绑定证明。 |
| F_HIST_INFRA_PERSISTENCE | 钓鱼基础设施持续存活 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_HIST_SCHEDULE_MATCH | 历史时刻模式一致 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_HIST_MULTI_IOC_SIEGE | 同资产多 IOC 围攻 | 不能完成 | 不能完成 | 缺正常基线；这两项修复不产生正常流量分母或基线。 |
| F_HIST_STAGE_PROGRESSION | 攻击阶段递进 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_HIST_COORD_PARAM_MATCH | 历史协同参数一致 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_HIST_EXERCISE | 登记演练平台命中 | 不能完成 | 不能完成 | 缺真实授权任务、演练或业务角色证明。 |
| F_IOC_NOVELTY | IOC 平台首现 | 不能完成 | 不能完成 | 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 |
| F_EXCL_SCAN_TASK | 已核验扫描任务 | 不能完成 | 不能完成 | 缺真实授权任务、演练或业务角色证明。 |
| F_EXCL_INFRA_ROLE | 已核验基础服务 | 不能完成 | 不能完成 | 缺真实授权任务、演练或业务角色证明。 |

## 23个语义槽位逐项核对

| 槽位 | 目标 | 修复前输入 | 修复后输入 | 仍需材料 |
|---|---|---|---|---|
| S01 | c2.command_intent | 不满足 | 不满足 | protocol_request |
| S02 | c2.command_exchange | 不满足 | 不满足 | protocol_request、protocol_response、pair |
| S03 | c2.ua_behavior_conflict | 不满足 | 不满足 | ua、protocol_request；还要求指定事实observed |
| S04 | c2.dns_encoded_intent | 不满足 | 不满足 | decode、decoded_payload；还要求指定事实observed |
| S05 | phishing.deception | 不满足 | 不满足 | page、host、brand_authorization |
| S06 | phishing.credential_action | 不满足 | 不满足 | credential_fields、protocol_request；还要求至少一项指定事实observed |
| S07 | exfil.sensitive_upload | 不满足 | 不满足 | protocol_request、volume、content_classification |
| S08 | exfil.chunk_sequence | 不满足 | 不满足 | chunk、volume、transfer_join |
| S09 | exploit.payload_intent | 不满足 | 不满足 | protocol_request、parsed_payload |
| S10 | protocol.response_meaning | 不满足 | 不满足 | protocol_request、protocol_response、pair |
| S11 | mining.protocol_intent | 不满足 | 不满足 | stratum_request、stratum_response、pair |
| S12/dga_lexical | c2.domain_lexical | 满足 | 满足 | 输入已满足；仍受模型调用和输出校验影响。 |
| S12/brand_semantic_impostor | phishing.deception | 不满足 | 不满足 | brand、host、brand_authorization |
| S13/command | payload.decoded_intent | 不满足 | 不满足 | decode、decoded_payload、protocol_request |
| S13/other | payload.decoded_intent | 不满足 | 不满足 | decode、decoded_payload、operation_context |
| S14 | review.benign_alternative | 不满足 | 不满足 | protocol_request、asset_role、task_context |
| S15 | review.stage_and_gaps | 满足 | 满足 | 输入已满足；仍受模型调用和输出校验影响。 |
| BT-S01 | botnet.coordination | 不满足 | 不满足 | group_member；还要求至少一项指定事实observed |
| SC01 | c2.role_schedule_conflict | 不满足 | 不满足 | asset_role、business_schedule |
| SC02 | botnet.group_alternative | 不满足 | 不满足 | group_member |
| SC03 | phishing.brand_field_conflict | 不满足 | 不满足 | brand、credential_fields、brand_authorization |
| R06 | history.activity_association | 不满足 | 不满足 | history |
| R07 | history.alternative_explanation | 不满足 | 不满足 | history |

## 修复后其余56种事实规则的主要阻塞

每种只归入一个主要原因，便于核对总数；不代表该规则只有一个缺项。

| 主要原因 | 数量 |
|---|---:|
| 生产无所需策略参数；部分规则另受样本/窗口限制。 | 4 |
| 全部当前事件为单日短窗口，未满足至少3个活跃日。 | 1 |
| 缺正常基线；这两项修复不产生正常流量分母或基线。 | 15 |
| 无失败前序；生产也未提供min_failures，不能把成功DNS后连接写成失败域激活。 | 1 |
| 缺可核验应用明文/HTTP字段；采样密文不能代替。 | 9 |
| 缺完整、已核验会话及长会话条件。 | 1 |
| 缺真实服务目录，不能仅凭常见端口判协议错配。 | 1 |
| 现场历史材料链路未供给；这两项修复不包含自动历史检索。阶段/协同还需独立证明。 | 7 |
| 缺独立来源链或已核验类型硬分；来源标签不等于独立性。 | 3 |
| 缺完整TLS材料及信任/指纹目录。 | 3 |
| 缺多资产、完整成员或群体绑定证明。 | 8 |
| 缺真实授权任务、演练或业务角色证明。 | 3 |
