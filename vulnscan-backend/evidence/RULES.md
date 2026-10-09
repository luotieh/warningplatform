# 59项事实规则实现清单

对应证据库v0.1；后端计算规则版本为evidence-algorithms-0.3。全部59项已有实际计算分支及成立/不成立用例；新增57项还有缺少依据的降级用例。这里的已实现不代表已获得生产数据、完成报告接入或通过真实告警验收。

规则参数及数据前提详见README。没有指定阈值的规则须由调用方注入配置；缺依据返回missing/ineligible。原定义中的旧版分值及类型门槛只作兼容说明，不作为本模块评分输出。

| fact_id | 名称 | 实现领域 | 未定阈值的配置项 |
| --- | --- | --- | --- |
| F_BEACON_PERIODIC | 严格周期信标 | 时间统计 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_BEACON_JITTER | 抖动周期信标 | 时间统计 | ljung_box_lags、median_relative_tolerance |
| F_FIXED_DAILY_WINDOW | 每天固定时间点 | 时间统计 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_MULTI_DAY_PERSIST | 跨日持续 | 时间统计 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_RATE_BURST | 命中突发 | 时间统计 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_RATE_RAMP | 速率阶梯上升 | 时间统计 | window_seconds |
| F_DNS_HIGH_ENTROPY | 长标签高基数子域（单资产） | DNS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_DNS_ENCODED_LABEL | 子域编码结构 | DNS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_DGA_LEXICAL | 词形随机性（单资产） | DNS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_NXDOMAIN_CLUSTER | NXDOMAIN 聚集（scope=asset，单资产） | DNS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_GROUP_NXDOMAIN_CLUSTER | 群体 NXDOMAIN 聚集（scope=asset_group） | 群体 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_FAILED_TO_ACTIVE | 失败域→激活连接 | DNS | min_failures |
| F_SHARED_DOMAIN_CLUSTER | 群体共同域名簇 | 群体 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HTTP_ENDPOINT_REPEAT | 端点重复回连 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HTTP_FIELD_ENCODING | 字段编码异常 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HTTP_UA_RARITY | UA 稀有/不一致 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HTTP_SIZE_STABILITY | 请求/响应尺寸稳定 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_LONG_LOW_SESSION | 长会话低频小流量 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_URL_ODD_AUTHORITY | URL 授权部分异常（弱欺骗） | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_URL_HOMOGLYPH | 同形混淆字符（强欺骗） | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_URL_BRAND_SUBDOMAIN_TRICK | 伪装子域（强欺骗） | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_BRAND_IMPOSTOR | 品牌仿冒 | HTTP/会话 | max_edit_distance |
| F_CRED_POST_STRUCTURE | 登录提交结构 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_FORM_CROSSSITE | 表单跨站提交 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_REDIRECT_CHAIN | 落地页→异站提交链 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_MULTI_REDIRECT_CHAIN | 多重短链跳转 | HTTP/会话 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_PROTOCOL_PORT_MISMATCH | 协议-端口错配 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_RARE_PORT | 稀有端口 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_DST_NOVELTY | 目的端点新颖 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_INFRA_RARITY | 目标基础设施稀有度 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_FANOUT_SINGLE_SRC | 单源目标扇出 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_PORT_SEQUENCE | 端口序列形态 | 网络/独立佐证 | difference_entropy_threshold（非单调序列） |
| F_SMALL_PACKET | 小包无载荷 | 网络/独立佐证 | small_payload_bytes |
| F_CONN_FAIL_RATE | 连接失败率 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_INDEPENDENT_RULE_CORROB | 独立规则交叉佐证 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_INDEPENDENT_INTEL_CORROB | 跨情报源独立命中 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_IOC_TYPE_CORROB | IOC 类型与行为证据一致 | 网络/独立佐证 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_TLS_SNI_MISMATCH | SNI 与目的不符 | TLS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_TLS_CERT_ANOMALY | 自签名/异常证书 | TLS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_TLS_JA_MISMATCH | JA3/JA4 指纹与声明不符 | TLS | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_MULTI_ASSET_IOC | 多资产同 IOC | 群体 | cluster_window_seconds |
| F_MULTI_ASSET_DIST | 聚集分布形态 | 群体 | subnet_entropy_min |
| F_TIME_COORDINATION | 多资产时间协同 | 群体 | bucket_seconds；可选max_lag_bins |
| F_COORD_FANOUT | 协同扫描/扇出 | 群体 | handoff_seconds（分工子路径） |
| F_INFECTION_CHAIN | 感染链传播 | 群体 | chain_window_seconds |
| F_SHARED_ENDPOINT | 共享目的端点 | 群体 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_FIRST_VISIT_CLUSTER | 首访时间聚集 | 群体 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_COORD_PATTERN_RECURRENCE | 协同模式跨日重复 | 群体 | bucket_seconds |
| F_HIST_ASSET_IOC_RECURRENCE | 同 IOC→同资产跨日复发 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HIST_GROUP_RECURRENCE | 群体+基础设施复发 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HIST_INFRA_PERSISTENCE | 钓鱼基础设施持续存活 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HIST_SCHEDULE_MATCH | 历史时刻模式一致 | 历史/授权 | kl_threshold |
| F_HIST_MULTI_IOC_SIEGE | 同资产多 IOC 围攻 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_HIST_STAGE_PROGRESSION | 攻击阶段递进 | 历史/授权 | CurrentStage来源证明；同IOC或核验战役；当前严格推进且历史不回退；见HISTORY.md |
| F_HIST_COORD_PARAM_MATCH | 历史协同参数一致 | 历史/授权 | parameter_relative_tolerance；同基础设施＋核验战役＋相同资产/完整群体成员；见HISTORY.md |
| F_HIST_EXERCISE | 登记演练平台命中 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_IOC_NOVELTY | IOC 平台首现 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_EXCL_SCAN_TASK | 已核验扫描任务 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
| F_EXCL_INFRA_ROLE | 已核验基础服务 | 历史/授权 | 按固定条件计算，或读取明确的外部基线/核验资料 |
