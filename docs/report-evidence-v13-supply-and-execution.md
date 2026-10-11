# 59事实与23语义：材料供应及真实执行矩阵

供应分类来自2026-10-10固定样本审计，不冒充本轮运行状态；本轮以execution字段为准

| ID | 原字段/材料 | 执行所需条件 | 实际完成状态 | 缺口及来源 |
|---|---|---|---|---|
| F_BEACON_PERIODIC | hit.time, packets | MinSamples、MinIntervalSeconds、MaxIntervalSeconds、MaxIntervalCV、MaxPacketsPerObservation；现默认8、5秒、86400秒、0.15、5包 | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_BEACON_JITTER | hit.time, packets | ljung_box_lags、median_relative_tolerance | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_FIXED_DAILY_WINDOW | hit.time | 至少3个活跃自然日，统一时区；逐条命中时间；实际每日时间分布及2小时窗口占比。不能以单日跨午夜替代3日。 | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_MULTI_DAY_PERSIST | hit.time | MinDays、Timezone；现默认2日、Asia/Shanghai；是否增加原设计days3展示需明确 | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_RATE_BURST | hit.time, locked_baseline | mean_per_5m、burst_ratio_p99 | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_RATE_RAMP | hit.time, locked_baseline | window_seconds | pending_real_report | capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_DNS_HIGH_ENTROPY | app.dns_query, hit.time, domain_baseline | unique_subdomain_ratio_p95、label_length_p95、query_rate_p95 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_DNS_ENCODED_LABEL | app.dns_query, hit.time, domain_baseline | 完整实际DNS问题名、逐标签编码匹配及代码解码验证；原目录列domain_baseline，当前结构检查不依赖基线，不以此阻断；意图另交S04。 | pending_real_report |  |
| F_DGA_LEXICAL | app.dns_query, dns.rcode, hit.time, baseline | bigram_log_probability_p05、vowel_ratio_p05/p95、length_p05/p95；BigramLogProbabilities语料 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母; dns_lexical_corpus:没有bigram语料及分位数来源 |
| F_NXDOMAIN_CLUSTER | app.dns_query, dns.rcode, hit.time, baseline | nxdomain_rate_p99 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_GROUP_NXDOMAIN_CLUSTER | app.dns_query, dns.rcode, hit.time, baseline | group_nxdomain_rate_p99 | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_FAILED_TO_ACTIVE | app.dns_query, dns.rcode, hit.time, baseline | min_failures | pending_real_report |  |
| F_SHARED_DOMAIN_CLUSTER | app.dns_query, hit.time, domain_baseline | domain_frequency_p01；逐注册域Frequency | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_ENDPOINT_REPEAT | app.http_method, app.http_host, app.http_url, app.user_agent, request_response_sizes, service_baseline | 可解析URL/Host/方法/时间、真实事务；至少6同端点请求，间隔CV；原目录列UA/尺寸/基线为上下文，实际重复判定不应误加无关依赖。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_HTTP_FIELD_ENCODING | app.http_method, app.http_host, app.http_url, app.user_agent, request_response_sizes, service_baseline | encoded_field_ratio_p95、encoded_field_length_p95 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_UA_RARITY | app.http_method, app.http_host, app.http_url, app.user_agent, request_response_sizes, service_baseline | ua_frequency、ua_frequency_p01 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_SIZE_STABILITY | app.http_method, app.http_host, app.http_url, app.user_agent, request_response_sizes, service_baseline | size_cv_p05、unique_size_ratio_p05 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_LONG_LOW_SESSION | session_id, session_start_end, directional_wire_bytes, volume_quality | 核验会话ID、开始/结束、上/下行字节、VolumeVerified、HitIDs；会话内真实周期样本；累计计数不能当各包载荷相加。 | pending_real_report | verified_sessions:64条命中保存exchange，共349个报文引用，存在重复或不完整; capture_quality:141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_URL_ODD_AUTHORITY | app.http_url, app.http_host, brand_authorized_domains | 完整URL授权部分与Host原文、解析结果、IP/编码主机及userinfo；保留弱欺骗属性；原品牌字段不构成该结构检查的强制目录依赖。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_URL_HOMOGLYPH | app.http_url, app.http_host, brand_authorized_domains | 实际URL/Host、IDNA Unicode/ASCII映射、混淆字符与skeleton规则版本、真实品牌授权域目录；不能仅凭非ASCII认定恶意。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; brand_registry:没有实际品牌与授权域目录 |
| F_URL_BRAND_SUBDOMAIN_TRICK | app.http_url, app.http_host, brand_authorized_domains | 实际子域、注册域、PSL版本、品牌词和真实授权域集合；明确品牌词所在层级与注册域不一致事实。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; brand_registry:没有实际品牌与授权域目录 |
| F_BRAND_IMPOSTOR | app.http_url, app.http_host, brand_authorized_domains | max_edit_distance | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包; brand_registry:没有实际品牌与授权域目录 |
| F_CRED_POST_STRUCTURE | transaction_id, app.http_method, redacted_body_field_names, page_origin, form_action, response.Location | 完整同事务请求：方法、实际字段名、字段来源和正文完整性；程序判定POST与凭据结构；字段值不是该结构算法必需。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_FORM_CROSSSITE | transaction_id, app.http_method, redacted_body_field_names, page_origin, form_action, response.Location | 页面真实来源URL、表单action、事务/页面关联、解析后的双方注册域；跨站正常业务背景保留。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_REDIRECT_CHAIN | transaction_id, app.http_method, redacted_body_field_names, page_origin, form_action, response.Location | 请求/响应同事务关联、完整Location/状态、ResponseURL、RedirectToTransactionID、最终提交方法与字段；程序验证链，禁止两条无关命中拼接。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_MULTI_REDIRECT_CHAIN | transaction_id, app.http_method, redacted_body_field_names, page_origin, form_action, response.Location | 连续多步请求/响应ID、状态、Location、目标URL、时间及链顺序；每条边真实绑定；短链外观不足。 | pending_real_report | http_records:本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_PROTOCOL_PORT_MISMATCH | app_proto, dst_port, service_inventory | 实际目的端口、由字节解析的AppProtocol/ProtocolParsed、真实Services及核验来源；protocol=tcp不是HTTP等应用协议。 | pending_real_report | service_registry:现场t_asset_srv及t_internal_srv_list均为0 |
| F_RARE_PORT | dst_ip, dst_port, asset_id, locked_baseline | port_frequency_p01；逐目的端口Frequency | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_DST_NOVELTY | dst_ip, dst_port, asset_id, locked_baseline | 当前精确端点(协议/地址/端口)、资产/设备、完整历史覆盖窗口与历史端点；只称覆盖历史内首次告警；原locked_baseline映射为历史覆盖而非凭空训练基线。 | pending_real_report |  |
| F_INFRA_RARITY | dst_ip, dst_port, asset_id, locked_baseline | infra_frequency_p01；ASN/国家/信誉组合Frequency | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母; infrastructure_registry:没有ASN、国家、信誉目录及对应频率资料 |
| F_FANOUT_SINGLE_SRC | asset_id, dst_ip, dst_port, hit.time, joint_snapshot | unique_targets_per_hour_p99 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_PORT_SEQUENCE | asset_id, dst_ip, dst_port, hit.time, joint_snapshot | difference_entropy_threshold | pending_real_report |  |
| F_SMALL_PACKET | payload_length, tcp_flags, hit.time | small_payload_bytes | pending_real_report |  |
| F_CONN_FAIL_RATE | payload_length, tcp_flags, hit.time | connection_failure_rate_p95 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_INDEPENDENT_RULE_CORROB | rule_metadata, intel_source_provenance, hard_fact_findings | 真实RuleRecord.ID、IndependenceGroup、OriginalSource和当前命中关系；规则共享同一IOC来源不算独立。 | pending_real_report | independent_rule_and_intel_metadata:保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_INDEPENDENT_INTEL_CORROB | rule_metadata, intel_source_provenance, hard_fact_findings | 同一类型化IOC、IntelRecord.ID/OriginalSource、来源转引链、提供者和时效；至少两个独立原始来源；仅多个feed名不够。 | pending_real_report | independent_rule_and_intel_metadata:保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_IOC_TYPE_CORROB | hard_type_scores, ioc_semantic_class | 查找原硬分真实生产者；无则登记未满足依赖。新增的报告权重不是原HardTypeScores，不能拿它反向证明该规则 | pending_real_report | independent_rule_and_intel_metadata:保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_TLS_SNI_MISMATCH | tls.sni, tls.cert, tls.ja3_or_ja4 | 实际SNI、证书SAN/CN集合及CDNExceptions/ExceptionsVerified；SNI与证书/目的的关系口径核对，不能拿SNI和目的IP直接字符串比。 | pending_real_report | tls_records:10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整; tls_trust_and_fingerprint_registry:没有证书信任、CDN例外、指纹客户端目录 |
| F_TLS_CERT_ANOMALY | tls.sni, tls.cert, tls.ja3_or_ja4 | 实际证书DER及TrustRootsDER、链；或独立已核验链结果、NotBefore/After、Issuer；TrustedIssuers及版本；按事件时刻验证有效期。 | pending_real_report | tls_records:10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整; tls_trust_and_fingerprint_registry:没有证书信任、CDN例外、指纹客户端目录 |
| F_TLS_JA_MISMATCH | tls.sni, tls.cert, tls.ja3_or_ja4 | 真实JA3/JA4握手计算字段/指纹、同客户端实际UA、FingerprintClients目录与核验版本；跨事务UA不能拼到该握手。 | pending_real_report | tls_records:10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整; tls_trust_and_fingerprint_registry:没有证书信任、CDN例外、指纹客户端目录 |
| F_MULTI_ASSET_IOC | verified_asset_id, ioc, endpoint_id, hit.time, joint_snapshot | cluster_window_seconds | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_MULTI_ASSET_DIST | verified_asset_id, ioc, endpoint_id, hit.time, joint_snapshot | subnet_entropy_min | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_TIME_COORDINATION | verified_asset_group, endpoint_id, hit.time, joint_snapshot, verified_association | bucket_seconds、max_lag_bins（可选但有效范围需校验） | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_COORD_FANOUT | verified_asset_group, endpoint_id, hit.time, joint_snapshot, verified_association | handoff_seconds | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_INFECTION_CHAIN | verified_asset_group, endpoint_id, hit.time, joint_snapshot, verified_association | chain_window_seconds | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_SHARED_ENDPOINT | verified_asset_id, ioc, endpoint_id, hit.time, joint_snapshot | endpoint_frequency、endpoint_frequency_p01 | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产; baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_FIRST_VISIT_CLUSTER | verified_asset_id, ioc, endpoint_id, hit.time, joint_snapshot | 至少3成员真实首访时间、端点、过去完整覆盖历史与当前联合窗口；不得把当前首次保存记录当首次访问。 | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_COORD_PATTERN_RECURRENCE | verified_asset_group, endpoint_id, hit.time, joint_snapshot, verified_association | bucket_seconds | pending_real_report | group_membership:1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体; group_observations:存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_HIST_ASSET_IOC_RECURRENCE | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | 30日真实历史，独立EventID、AssetIDs、同类型IOC、时间与来源；≥2日/独立事件；所有审核状态参与，原+20/-20不执行。 | pending_real_report |  |
| F_HIST_GROUP_RECURRENCE | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | 当前与历史完整成员全集及核验、GroupID、相同IOC/族/精确端点基础设施和跨周时间；同GroupID不代替集合核验；原加减分不执行。 | pending_real_report |  |
| F_HIST_INFRA_PERSISTENCE | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | 同实际IOC、不同独立资产、按日活动与连续日定义，当前AsOf/回溯范围；所有历史参与；不是证明基础设施全天在线。 | pending_real_report |  |
| F_HIST_SCHEDULE_MATCH | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | kl_threshold | pending_real_report |  |
| F_HIST_MULTI_IOC_SIEGE | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | distinct_ioc_families_p99 | pending_real_report | baselines:没有可信来源登记，也没有完整正常流量分母 |
| F_HIST_STAGE_PROGRESSION | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | CurrentStage及独立来源、历史Stage、同资产与同IOC/核验CampaignID/活动链、时序；当前阶段必须实际参与，不串无关历史。 | pending_real_report | campaign_and_stage_proofs:没有同战役、CurrentStage及完整协同参数来源证明 |
| F_HIST_COORD_PARAM_MATCH | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | parameter_relative_tolerance | pending_real_report | campaign_and_stage_proofs:没有同战役、CurrentStage及完整协同参数来源证明 |
| F_HIST_EXERCISE | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | 真实演练登记ID、AssetID/域名/目标/角色/TaskType、有效起止和来源；与当前活动匹配；旧PH分数封顶不是本任务概率公式。 | pending_real_report | authorization_records:evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |
| F_IOC_NOVELTY | verified_adjudication, history_snapshot, asset_id, ioc, hit.time | 类型化IOC、完整可追溯历史检索、LookbackStart/AsOf与0匹配；历史达到上限/超时不能输出首现；审核状态不作过滤。 | pending_real_report |  |
| F_EXCL_SCAN_TASK | approved_task_id, verified_scanner, target_range, time_window | 实际任务ID、scanner主体、目标集合、端口/协议、授权有效时段；与本次通信逐项匹配；不能由模型猜授权。 | pending_real_report | authorization_records:evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |
| F_EXCL_INFRA_ROLE | verified_role, verified_matching_task | 实际资产业务角色、匹配任务、服务/目标/协议及有效时间；角色命中只提供业务解释，不能自动排除所有恶意。 | pending_real_report | authorization_records:evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |
| S01/ | protocol_request, direction | 可读协议、可信方向；strong须同事务双向语义对应；不证明执行成功 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S02/ | protocol_request, protocol_response, pair | 同事务真实请求应答；排除文档与日志回显 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令; protocol_response:没有与上述请求绑定的可读应用应答; pair:exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S03/ | ua, protocol_request | 重复端点事实及实际UA；浏览器声明不足 | pending_real_report | ua:没有HTTP UA明文；SNI不是UA; protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S04/ | domain, decode, decoded_payload | 编码标签事实及代码验证解码链；考虑追踪token | pending_real_report | decode:本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码; decoded_payload:没有可核验解码链对应明文 |
| S05/ | page, host, brand_authorization | 页面正文、Host、核验品牌授权域；strong须明确仿冒依据 | pending_real_report | page:没有页面正文; host:DNS名及SNI存在，但不是HTTP Host字段; brand_authorization:没有真实授权域目录 |
| S06/ | credential_fields, protocol_request | 同请求字段名、方法、目的及行动事实；只解释收集意图 | pending_real_report | credential_fields:没有当前请求中的凭据字段明文; protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S07/ | protocol_request, direction, volume, content_classification | 完整请求、可信方向与体量、内容分类依据；不证明送达 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令; volume:可以计算已保存报文载荷长度，不能证明整个上传事务体量; content_classification:没有实际上传内容及敏感分类来源，当前适配不自动生产 |
| S08/ | chunk, volume, transfer_join | 至少两个可靠关联事务、块序号及可信体量；禁止拼接无关命中 | pending_real_report | chunk:没有可核验的分块上传字段、块序号与事务体量; volume:可以计算已保存报文载荷长度，不能证明整个上传事务体量; transfer_join:没有跨块/事务的真实传输关联标识 |
| S09/ | protocol_request, parsed_payload, direction | 已解析请求载荷、方法、目标协议及可信方向；不证明利用成功 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令; parsed_payload:没有可读请求正文，握手/密文不能当利用载荷 |
| S10/ | protocol_request, protocol_response, pair | 同事务真实双向应答；HTTP200不证明执行 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令; protocol_response:没有与上述请求绑定的可读应用应答; pair:exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S11/ | stratum_request, stratum_response, pair | 实际Stratum方法、参数和应答；不重复协议事实 | pending_real_report | stratum_request:未发现真实mining方法和参数; stratum_response:未发现可关联Stratum应答; pair:exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S12/dga_lexical | domain, lexical_context | 原始域名及词形上下文；随机串不自动等于DGA | pending_real_report |  |
| S12/brand_semantic_impostor | brand, host, brand_authorization | 品牌、实际授权域与仿冒关系；仅品牌词最多weak | pending_real_report | brand:没有已核验页面品牌或品牌声明; host:DNS名及SNI存在，但不是HTTP Host字段; brand_authorization:没有真实授权域目录 |
| S13/command | decode, decoded_payload, protocol_request, direction | 代码验证解码链及实际命令上下文；strong遵循S01 | pending_real_report | decode:本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码; decoded_payload:没有可核验解码链对应明文; protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S13/other | decode, decoded_payload, operation_context | 代码验证解码链及独立操作上下文；解码成功不等于恶意 | pending_real_report | decode:本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码; decoded_payload:没有可核验解码链对应明文; operation_context:没有满足绑定的解码后操作上下文 |
| S14/ | protocol_request, asset_role, task_context | 实际流量、事实规则、资产角色及任务上下文；仅记录异议 | pending_real_report | protocol_request:本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令; asset_role:有资产登记，但asset_type=ip不代表业务角色；语义适配当前主要依赖授权角色; task_context:没有授权任务资料 |
| S15/ | visibility, gaps | 接受的事实、可见范围及缺项；成功性须独立证据 | pending_real_report |  |
| BT-S01/ | group_member | 核验群体及协同硬事实；最多5资产；不替代硬门槛 | pending_real_report | group_member:没有已核验群体成员和角色，本批只绑定一个资产 |
| SC01/ | asset_role, business_schedule, time_distribution | 核验角色、业务作息及实际时间分布；夜间服务器运行不自动异常 | pending_real_report | asset_role:有资产登记，但asset_type=ip不代表业务角色；语义适配当前主要依赖授权角色; business_schedule:没有业务作息资料，当前输入结构也未自动供给该材料 |
| SC02/ | group_member | 核验群体角色与实际行为摘要；供人工解释 | pending_real_report | group_member:没有已核验群体成员和角色，本批只绑定一个资产 |
| SC03/ | brand, credential_fields, brand_authorization | 实际品牌、字段级引用及核验授权背景；不替代欺骗或行动门槛 | pending_real_report | brand:没有已核验页面品牌或品牌声明; credential_fields:没有当前请求中的凭据字段明文; brand_authorization:没有真实授权域目录 |
| R06/ | history, current_pattern | 引用历史活动与当前模式，解释同IOC/资产关联；相似不自动等于同战役 | pending_real_report |  |
| R07/ | history, current_pattern | 使用全部关联历史比较业务解释与异常解释，不按审核状态筛选，不以相似认定误报 | pending_real_report |  |

全部实例、指标、参数、范围、来源与报告ID见同名JSON；待生成状态不计完成。
范围外依赖：正常流量分母/基线、实际角色与作息、授权工单、品牌/服务/基础设施及信任目录、群体/战役/阶段证明、合法应用明文等；不通过修改采集或数据库结构在本期补造。
