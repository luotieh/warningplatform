# 真实材料供应盘点

检查日期：2026-10-10。结论针对已核对的7个真实事件、141条原始命中及现场资料登记，不是全平台所有事件的输入覆盖率。

## 先看结果

按59项事实规则与23个语义槽位逐项核对材料来源，统计如下：

| 层 | 现有来源可补齐主要材料 | 只能部分补齐 | 本批未找到必要材料或来源 | 合计 |
|---|---:|---:|---:|---:|
| 事实规则 | 8 | 10 | 41 | 59 |
| 语义槽位 | 4 | 0 | 19 | 23 |
| 合计 | **12** | **10** | **60** | **82** |

**这不是“现在能成功执行12项”的统计。** “可补齐”指已经找到真实来源，可以通过读取、解析、关联补充主要材料；还要检查范围完整性、样本数、策略参数及具体字段。当前仍有70项不能认定材料完整，其中10项已有部分材料，60项在本批事件里缺少必要素材或现场资料来源。

特别是：TLS/DNS事件本来就不一定有HTTP、页面、凭据提交或Stratum材料。它们在这批事件中没有输入，不能全部算作代码缺陷，也不应为了跑满82项伪造输入。后续实现应再将“不适用”“输入缺失”“样本不足”“策略未配置”分开记录。

按输入契约分类也做了一份统计：

| 输入契约 | 可补齐 | 部分可补齐 | 未找到必要材料或来源 | 合计 |
|---|---:|---:|---:|---:|
| 事实侧输入类别 | 4 | 5 | 10 | 19 |
| 语义侧材料类型 | 8 | 4 | 19 | 31 |

两侧共有50个契约项，但不是50个独立物理来源：例如历史、DNS等资料可以被两侧复用。逐类原因、补齐路径及82项对应表在本文后半部分；可筛选的完整表另存为CSV，结构化结果另存为JSON。

## 真实来源核验

本次只读查询和文件检查，没有导入测试材料、调用模型、生成报告或改变事件状态。

- 从已保存证据结果的来源引用定位到141条真实命中，按hit_id主键集中读取原始记录。
- 141条命中都引用了一个PCAP文件；在服务器`/opt/ta_node/data/evidence`下全部找到并读取。141个文件合计55017字节，各保存1个报文，格式检查没有错误。
- PCAP内容与相应命中的packet_hex全部一致。按PCAP时间戳和报文字节哈希去重，共139个物理报文，说明IOC命中数不能直接作为物理包数。
- 141条代表帧中，135条通过“IPv4报文长度已包含且未分片”的初步检查，6条不满足。全部141条都缺显式capture_truncated标记。captured_length等于wire_length不能单独证明应用内容完整；这些初步检查也不代替五元组一致性、TCP重组和字段冲突核验。
- 原始app字段中，10条命中有tls_sni，9条有dns_query，4条有dns_answers；5条代表帧有TLS握手记录形态，部分ClientHello长度不足。没有从密文猜测正文。
- 64条命中还保存exchange，两侧合计349个报文引用。这些引用会重复，初步IPv4长度检查有321个通过、28个未通过；不是349个独立完整报文，也不是完整会话。
- 本批代表帧和exchange报文边界未发现HTTP请求/响应明文；存在1条SSH标识。此检查不排除跨TCP段拼接后有应用消息，因此“未发现”不是全会话不存在证明。当前没有已验证的HTTP明文来源。
- 当前流量库有1686条traffic_assets登记，但资产地址不等于业务角色、NAT归属或Botnet群体证明。
- 当前evidence_sources、evidence_inputs、evidence_source_audit均无登记记录；t_asset_srv、t_internal_srv_list、流量tasks表均为0。没有因为表存在就认定资料已具备。

## 12项现有来源可以补齐哪些材料

事实侧8项：

| 规则 | 可以从现有资料补的内容 | 仍需注意 |
|---|---|---|
| F_DNS_ENCODED_LABEL | 真实查询名、标签、报文来源及编码结构 | 本批已保存结果为未观察到编码标签；不能强行生成编码载荷 |
| F_PORT_SEQUENCE | 完整端口集合与时间顺序，例如自有VPS的12端口 | 非单调序列仍需配置差分熵阈值；端口集合本身应独立保留为基础事实 |
| F_SMALL_PACKET | 可解析帧中的实际载荷长度分布 | small_payload_bytes策略尚须明确；报文载荷字节不等于会话上传体量 |
| F_DST_NOVELTY | 历史命中的实际协议、目标和端口 | 当前历史适配未给平台历史写入精确Endpoint；需要补字段，并核对历史覆盖窗口 |
| F_IOC_NOVELTY | 已保存历史库中的IOC出现记录 | 无匹配不等于真实网络首现；检索截断、库覆盖不足时不能成立首现结论 |
| F_HIST_ASSET_IOC_RECURRENCE | 同资产同IOC的历史事件和日期 | 30天声明窗口、独立事件与跨日样本必须实际满足；不按审核状态筛选 |
| F_HIST_INFRA_PERSISTENCE | 相同IOC在不同资产及日期的历史访问 | 本批只绑定一个分析资产，不足以成立多资产持续访问；仍可供给真实历史记录 |
| F_HIST_SCHEDULE_MATCH | 历史与当前命中的小时分布 | 当前kl_threshold未配置；历史过少或查询截断仍不能作完整比较 |

语义侧4项：S12/dga_lexical、S15、R06、R07。可分别供给真实域名与词形上下文、可见范围与缺项、全部匹配历史与当前行为。S12的词形解释不等于DGA统计检验；R06/R07需部署已有的自动历史接入；S15当前还受上下文预算影响。模型调用可用性另行检查，不属于材料供应统计。

## 不能完整补齐的主要原因

### 补充核对：capture_quality缺口怎样发生

这不是全部缺口。capture_quality只是时间序列、部分会话等规则引用的一类质量条件，同一原因在多个规则中重复出现，不代表出现了多个独立取数故障。

141条命中存库的原始raw_packet都没有capture_truncated，所以缺失发生在后端证据计算之前。后端适配器只读取这个显式标记，没有利用实际报文重新核验并生产质量状态；snapshotPayload也以标记是否存在判断完整性。引擎随后要求全局CaptureTruncated明确为false，才把complete判为true。结果是“标记未提供”被放大为多个时间/协议规则不可用，即使地址、端口、时间或某个完整报文已经真实存在。

6条IPv4长度不一致报文全部保存1600字节，但IPv4长度加以太网头需要的字节数分别为2191、1885、1853、2962、2962、2848。元数据captured_length和wire_length均写成1600，PCAP也只保留相同片段。因此它们不满足完整IP数据报核验，不能凭cap等于wire判为完整。

服务器默认ta_node.yaml中有snaplen=1600，与这个边界吻合；但当前运行进程使用ta_node.offline.yaml，其snaplen=65535，pcap_file为空且监听真实网卡。配置名和device_id中的offline不能据此证明在回放。仅凭现在的配置还不能确认历史报文在哪个环节被裁成1600字节：可能是先前抓包、报文投影或证据保存。需要继续核对采集实现与当时配置，不能直接把默认文件当成事故根因。

当前运行配置还设置save_full_session_pcap=false，并对每事务报文数、重组字节数设上限；本批实际PCAP各1包。因此PCAP附件本身不能作为完整会话证明；exchange可能另存更大范围的片段，但仍须分别核验。

修复方向应拆开报文长度/截断质量、协议消息完整性、会话完整性、告警时序覆盖。对可核验字段保留事实，对缺少字节的报文记录实际边界；不批量补capture_truncated=false，也不让密文/正文不足使端口和时间事实一起失效。

1. **现场没有独立资料。** 正常流量基线、品牌与授权域、实际服务目录、授权工单、DNS词形语料、基础设施信誉、TLS信任/指纹目录、业务作息均没有现成可核验来源。不能用模型输出或常见端口表代替。
2. **原始捕获就是局部材料。** PCAP一文件一报文，exchange也是有界片段；不能保证完整连接状态、完整会话上下行字节或跨事务链。补读现有PCAP能复核报文，不能找回未保存的包。
3. **内容加密或缺少应用素材。** 有TLS、SNI和报文，不代表有HTTP页面、UA、凭据字段、请求正文或敏感上传内容。TLS正文需要真实解密/代理日志等来源，不能靠语义猜测。
4. **关系证明缺失。** 同资产不是同战役，1686个地址不是已核验群体成员。阶段递进、群体协同仍需明确对象、成员、时间与来源绑定。
5. **已有字段没有正确生产到输入。** 截断状态、完整端口分布、报文标志、历史精确端点、DNS应答IP与后续连接关系等有真实材料可解析或关联，但当前适配不完整。应优先解决这一类。
6. **策略或样本条件未满足。** 这是执行就绪问题，不应混成“数据没采集”。例如12个端口已有，但差分熵阈值缺失；2条微秒间隔记录不会因为补材料而变成可靠的周期样本。

同一证据可能同时缺多项资料，原因类别有重叠，不把它们相加当作独立缺口数量。后面的逐项表保留全部依赖。

## 下一步供应实现的优先顺序

第一批应实现已有材料的补充生产：逐报文质量核验、协议与载荷长度、完整端点分布、DNS问答关联、exchange去重及可见会话片段、历史精确端点与应答IOC绑定。每项输出保留来源、范围、版本和不能补齐的原因。

尤其先恢复两条真实事实链：自有VPS“约3秒涉及12端口”；DNS回答中的104.21.60.213与约0.503秒后同资产通联的关联。后者是解析与通联关联，当前没有NXDOMAIN失败前序，不能冒充F_FAILED_TO_ACTIVE。

第二批需要实际资料来源：服务目录、授权任务、品牌目录、正常流量基线、词形语料、TLS目录和业务作息。没有资料时应准确显示缺哪类来源，而不是默认通过核验。

本次完成的是盘点与原因定位；**尚未修改生产输入适配，也未把12项计为现场算法验收通过。** 基础地址、端口、DNS问答等确定观测应额外保留，不能等异常规则成立后才交给报告。

## 统计文件与复核边界

- `2026-10-10-evidence-input-supply.csv`：82行证据映射，可按材料分类和原因筛选。
- `2026-10-10-evidence-input-supply.json`：50个输入契约项及82项证据映射。
- 现场原始材料、PCAP内容与解析统计在本机`F:/Temp/traffic-report-audit`，未放入Git仓库。
- 59项及23槽位从实际运行目录函数Definitions/FactInputs/SemanticInputContracts导出；逐字段补充检查参考network_rules、history_rules、semantic_prerequisites及输入适配实现。槽位材料存在也不代表其AllFacts/AnyFacts已经成立。

详细表中的“可补齐”始终指材料来源可获取，不能据此跳过样本、策略、完整性或绑定校验；“本批未找到”不能外推为其他事件、其他节点或未来永远没有。

## 逐类材料供应表

分类统计是输入契约项；同一物理来源可供给多个契约项。

| 层 | 材料类型 | 分类 | 原因 | 补齐路径 |
|---|---|---|---|---|
| 事实 | time_series | 现有来源可补齐 | 固定快照已保存141条真实命中时间 | 按资产、端点、设备汇总；跨日分析需声明联合窗口 |
| 事实 | network_records | 现有来源可补齐 | 原始帧、五元组和端口真实存在 | 解析全量命中，保留端口分布与TCP标志 |
| 事实 | dns_records | 现有来源可补齐 | 9条命中带查询名，4条带回答；原始DNS报文存在 | 区分查询与应答，解析rcode，按物理报文去重 |
| 事实 | history | 现有来源可补齐 | 平台事件库已有真实历史记录 | 有界检索全部匹配历史；补端点与DNS应答IOC绑定，声明覆盖范围 |
| 事实 | capture_quality | 只能部分补齐 | 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 | 逐报文核验cap/wire、IP长度、分片和元数据冲突；不得全局补false |
| 事实 | tls_records | 只能部分补齐 | 10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整 | 按TCP序列重组可见握手；SNI不冒充证书或指纹 |
| 事实 | verified_sessions | 只能部分补齐 | 64条命中保存exchange，共349个报文引用，存在重复或不完整 | 去重、校验序号与双向状态；缺包会话只保留观察量 |
| 事实 | group_observations | 只能部分补齐 | 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 | 跨事件检索独立资产观察；未证实成员与群体范围前不得宣称群体 |
| 事实 | independent_rule_and_intel_metadata | 只能部分补齐 | 保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 | 保留来源背景；补来源链与规则独立组，类型硬分需要实际生产过程 |
| 事实 | authorization_records | 本批未找到必要材料或来源 | evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 | 接实际授权工单、扫描计划、演练登记，包含主体、目标、端口和有效期 |
| 事实 | baselines | 本批未找到必要材料或来源 | 没有可信来源登记，也没有完整正常流量分母 | 新增正常流量采集与基线训练，不能从告警命中训练正常基线 |
| 事实 | brand_registry | 本批未找到必要材料或来源 | 没有实际品牌与授权域目录 | 登记真实品牌及授权域；域名含品牌词不能替代目录 |
| 事实 | campaign_and_stage_proofs | 本批未找到必要材料或来源 | 没有同战役、CurrentStage及完整协同参数来源证明 | 接关联活动证明；不得把同资产或模型标签当战役证明 |
| 事实 | dns_lexical_corpus | 本批未找到必要材料或来源 | 没有bigram语料及分位数来源 | 引入有版本、有训练范围的词形语料 |
| 事实 | group_membership | 本批未找到必要材料或来源 | 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体 | 补真实资产身份、NAT/代理归属与群体分析范围 |
| 事实 | http_records | 本批未找到必要材料或来源 | 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 | 接代理/网关HTTP日志或合法明文来源；不从TLS密文猜正文 |
| 事实 | infrastructure_registry | 本批未找到必要材料或来源 | 没有ASN、国家、信誉目录及对应频率资料 | 接实际基础设施资料并保存版本；另需正常基线 |
| 事实 | service_registry | 本批未找到必要材料或来源 | 现场t_asset_srv及t_internal_srv_list均为0 | 接实际服务发现/服务目录；不能用常见端口猜真实协议 |
| 事实 | tls_trust_and_fingerprint_registry | 本批未找到必要材料或来源 | 没有证书信任、CDN例外、指纹客户端目录 | 接证书和信任/指纹目录；完整握手不等于这些外部资料 |
| 语义 | direction | 现有来源可补齐 | 已绑定资产与真实源/目的地址可确定相对于资产的报文方向 | 生成绑定事务的入/出站方向；不推断攻击发起方 |
| 语义 | domain | 现有来源可补齐 | 已保存9条DNS查询名 | 使用真实问题字段，不把IP情报描述域名当查询名 |
| 语义 | lexical_context | 现有来源可补齐 | 原始域名及其查询来源可追溯 | 供词形语义解释；不冒充统计语料 |
| 语义 | visibility | 现有来源可补齐 | 快照成员、已读取/绑定数量与范围已保存 | 明确告警快照而非全部通信 |
| 语义 | gaps | 现有来源可补齐 | 规则结果包含具体reason_code | 按字段和规则整理缺项 |
| 语义 | history | 现有来源可补齐 | 已有平台历史事件 | 全部匹配历史参与，不按审核状态筛选 |
| 语义 | current_pattern | 现有来源可补齐 | 当前真实端点、命中时间和规则结果已存在 | 加入端口分布/DNS问答等基础观测，不只拼接missing结果 |
| 语义 | time_distribution | 现有来源可补齐 | 141条真实命中含微秒时间 | 按固定范围分桶；样本不足与未采集分开 |
| 语义 | asset_role | 只能部分补齐 | 有资产登记，但asset_type=ip不代表业务角色；语义适配当前主要依赖授权角色 | 接实际业务角色，不能由IP或备注自动证明 |
| 语义 | host | 只能部分补齐 | DNS名及SNI存在，但不是HTTP Host字段 | 保留各自协议来源；取得HTTP后再生成host材料 |
| 语义 | pair | 只能部分补齐 | exchange有两侧报文，但不是已核验同事务应用请求应答 | 先重组核验应用消息与序号/事务ID，不能把ACK当业务应答 |
| 语义 | volume | 只能部分补齐 | 可以计算已保存报文载荷长度，不能证明整个上传事务体量 | 区分观察量、累计计数与核验事务字节 |
| 语义 | brand | 本批未找到必要材料或来源 | 没有已核验页面品牌或品牌声明 | 取得实际页面并绑定品牌目录 |
| 语义 | brand_authorization | 本批未找到必要材料或来源 | 没有真实授权域目录 | 接品牌授权资料 |
| 语义 | business_schedule | 本批未找到必要材料或来源 | 没有业务作息资料，当前输入结构也未自动供给该材料 | 接业务登记和明确作息材料适配 |
| 语义 | chunk | 本批未找到必要材料或来源 | 没有可核验的分块上传字段、块序号与事务体量 | 取得明文请求并解析真实分块协议 |
| 语义 | content_classification | 本批未找到必要材料或来源 | 没有实际上传内容及敏感分类来源，当前适配不自动生产 | 接内容分类依据与事务绑定 |
| 语义 | credential_fields | 本批未找到必要材料或来源 | 没有当前请求中的凭据字段明文 | 取得完整请求；情报说钓鱼不能替代字段 |
| 语义 | decode | 本批未找到必要材料或来源 | 本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码 | 仅对真实编码字段验证解码链，不能伪造 |
| 语义 | decoded_payload | 本批未找到必要材料或来源 | 没有可核验解码链对应明文 | 由真实编码链产生并保存关联 |
| 语义 | group_member | 本批未找到必要材料或来源 | 没有已核验群体成员和角色，本批只绑定一个资产 | 取得真实多资产资料及明确分组 |
| 语义 | operation_context | 本批未找到必要材料或来源 | 没有满足绑定的解码后操作上下文 | 从同条实际请求或操作日志取得 |
| 语义 | page | 本批未找到必要材料或来源 | 没有页面正文 | 接实际页面或HTTP响应明文 |
| 语义 | parsed_payload | 本批未找到必要材料或来源 | 没有可读请求正文，握手/密文不能当利用载荷 | 取得并解析明文请求正文 |
| 语义 | protocol_request | 本批未找到必要材料或来源 | 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 | 取得可读应用请求，或扩展协议适配后保持原始含义 |
| 语义 | protocol_response | 本批未找到必要材料或来源 | 没有与上述请求绑定的可读应用应答 | 取得同事务响应并验证关联 |
| 语义 | stratum_request | 本批未找到必要材料或来源 | 未发现真实mining方法和参数 | 有真实Stratum时解析；不从443端口猜挖矿 |
| 语义 | stratum_response | 本批未找到必要材料或来源 | 未发现可关联Stratum应答 | 保留实际请求/响应ID关联 |
| 语义 | task_context | 本批未找到必要材料或来源 | 没有授权任务资料 | 接实际业务/授权任务 |
| 语义 | transfer_join | 本批未找到必要材料或来源 | 没有跨块/事务的真实传输关联标识 | 取得分块ID与关联证据；当前适配未生产 |
| 语义 | ua | 本批未找到必要材料或来源 | 没有HTTP UA明文；SNI不是UA | 接实际HTTP请求字段 |

## 59项事实规则对应供应情况

| 规则 | 名称 | 分类 | 缺口或核验要求 |
|---|---|---|---|
| F_BEACON_PERIODIC | 严格周期信标 | 只能部分补齐 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_BEACON_JITTER | 抖动周期信标 | 只能部分补齐 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_FIXED_DAILY_WINDOW | 每天固定时间点 | 只能部分补齐 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_MULTI_DAY_PERSIST | 跨日持续 | 只能部分补齐 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_RATE_BURST | 命中突发 | 本批未找到必要材料或来源 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_RATE_RAMP | 速率阶梯上升 | 只能部分补齐 | capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_DNS_HIGH_ENTROPY | 长标签高基数子域（单资产） | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_DNS_ENCODED_LABEL | 子域编码结构 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_DGA_LEXICAL | 词形随机性（单资产） | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母；dns_lexical_corpus: 没有bigram语料及分位数来源 |
| F_NXDOMAIN_CLUSTER | NXDOMAIN 聚集（scope=asset，单资产） | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_GROUP_NXDOMAIN_CLUSTER | 群体 NXDOMAIN 聚集（scope=asset_group） | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_FAILED_TO_ACTIVE | 失败域→激活连接 | 只能部分补齐 | 跨事件DNS→连接尚需关联；本批DNS应答rcode均为0，缺失败前序。不得把当前DNS解析→连接写成失败域激活 |
| F_SHARED_DOMAIN_CLUSTER | 群体共同域名簇 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_ENDPOINT_REPEAT | 端点重复回连 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_HTTP_FIELD_ENCODING | 字段编码异常 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_UA_RARITY | UA 稀有/不一致 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_HTTP_SIZE_STABILITY | 请求/响应尺寸稳定 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_LONG_LOW_SESSION | 长会话低频小流量 | 只能部分补齐 | verified_sessions: 64条命中保存exchange，共349个报文引用，存在重复或不完整；capture_quality: 141条均缺capture_truncated；135条帧满足完整IPv4长度检查，6条不满足 |
| F_URL_ODD_AUTHORITY | URL 授权部分异常（弱欺骗） | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_URL_HOMOGLYPH | 同形混淆字符（强欺骗） | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；brand_registry: 没有实际品牌与授权域目录 |
| F_URL_BRAND_SUBDOMAIN_TRICK | 伪装子域（强欺骗） | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；brand_registry: 没有实际品牌与授权域目录 |
| F_BRAND_IMPOSTOR | 品牌仿冒 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包；brand_registry: 没有实际品牌与授权域目录 |
| F_CRED_POST_STRUCTURE | 登录提交结构 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_FORM_CROSSSITE | 表单跨站提交 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_REDIRECT_CHAIN | 落地页→异站提交链 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_MULTI_REDIRECT_CHAIN | 多重短链跳转 | 本批未找到必要材料或来源 | http_records: 本批代表帧及exchange报文边界未发现HTTP请求/应答明文；主要为TLS、DNS和TCP小包 |
| F_PROTOCOL_PORT_MISMATCH | 协议-端口错配 | 本批未找到必要材料或来源 | service_registry: 现场t_asset_srv及t_internal_srv_list均为0 |
| F_RARE_PORT | 稀有端口 | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_DST_NOVELTY | 目的端点新颖 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_INFRA_RARITY | 目标基础设施稀有度 | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母；infrastructure_registry: 没有ASN、国家、信誉目录及对应频率资料 |
| F_FANOUT_SINGLE_SRC | 单源目标扇出 | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_PORT_SEQUENCE | 端口序列形态 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_SMALL_PACKET | 小包无载荷 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_CONN_FAIL_RATE | 连接失败率 | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_INDEPENDENT_RULE_CORROB | 独立规则交叉佐证 | 只能部分补齐 | independent_rule_and_intel_metadata: 保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_INDEPENDENT_INTEL_CORROB | 跨情报源独立命中 | 只能部分补齐 | independent_rule_and_intel_metadata: 保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_IOC_TYPE_CORROB | IOC 类型与行为证据一致 | 只能部分补齐 | independent_rule_and_intel_metadata: 保存IOC来源、标签、规则标识；未核验来源独立性或类型硬分 |
| F_TLS_SNI_MISMATCH | SNI 与目的不符 | 本批未找到必要材料或来源 | tls_records: 10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整；tls_trust_and_fingerprint_registry: 没有证书信任、CDN例外、指纹客户端目录 |
| F_TLS_CERT_ANOMALY | 自签名/异常证书 | 本批未找到必要材料或来源 | tls_records: 10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整；tls_trust_and_fingerprint_registry: 没有证书信任、CDN例外、指纹客户端目录 |
| F_TLS_JA_MISMATCH | JA3/JA4 指纹与声明不符 | 本批未找到必要材料或来源 | tls_records: 10条命中保存SNI；5条代表帧为TLS握手形态，部分ClientHello不完整；tls_trust_and_fingerprint_registry: 没有证书信任、CDN例外、指纹客户端目录 |
| F_MULTI_ASSET_IOC | 多资产同 IOC | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_MULTI_ASSET_DIST | 聚集分布形态 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_TIME_COORDINATION | 多资产时间协同 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_COORD_FANOUT | 协同扫描/扇出 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_INFECTION_CHAIN | 感染链传播 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_SHARED_ENDPOINT | 共享目的端点 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产；baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_FIRST_VISIT_CLUSTER | 首访时间聚集 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_COORD_PATTERN_RECURRENCE | 协同模式跨日重复 | 本批未找到必要材料或来源 | group_membership: 1686条资产地址不是群体成员或NAT归属证明；本批无多资产群体；group_observations: 存在真实资产登记和单资产命中，但本批材料只绑定一个分析资产 |
| F_HIST_ASSET_IOC_RECURRENCE | 同 IOC→同资产跨日复发 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_HIST_GROUP_RECURRENCE | 群体+基础设施复发 | 本批未找到必要材料或来源 | history.CurrentMemberIDs/GroupMembershipVerified: 没有完整核验群体绑定 |
| F_HIST_INFRA_PERSISTENCE | 钓鱼基础设施持续存活 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_HIST_SCHEDULE_MATCH | 历史时刻模式一致 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_HIST_MULTI_IOC_SIEGE | 同资产多 IOC 围攻 | 本批未找到必要材料或来源 | baselines: 没有可信来源登记，也没有完整正常流量分母 |
| F_HIST_STAGE_PROGRESSION | 攻击阶段递进 | 本批未找到必要材料或来源 | campaign_and_stage_proofs: 没有同战役、CurrentStage及完整协同参数来源证明 |
| F_HIST_COORD_PARAM_MATCH | 历史协同参数一致 | 本批未找到必要材料或来源 | campaign_and_stage_proofs: 没有同战役、CurrentStage及完整协同参数来源证明 |
| F_HIST_EXERCISE | 登记演练平台命中 | 本批未找到必要材料或来源 | authorization_records: evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |
| F_IOC_NOVELTY | IOC 平台首现 | 现有来源可补齐 | 已有真实来源，仍须检查具体字段、窗口、阈值与样本数；不是执行成功承诺 |
| F_EXCL_SCAN_TASK | 已核验扫描任务 | 本批未找到必要材料或来源 | authorization_records: evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |
| F_EXCL_INFRA_ROLE | 已核验基础服务 | 本批未找到必要材料或来源 | authorization_records: evidence_sources/evidence_inputs无记录，流量tasks为0；没有授权扫描或演练资料 |

## 23个语义槽位对应供应情况

S12和S13各有两个独立子型，按运行契约分别计数。

| 槽位 | 目标/子型 | 分类 | 缺口或核验要求 |
|---|---|---|---|
| S01 | c2.command_intent | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S02 | c2.command_exchange | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令；protocol_response: 没有与上述请求绑定的可读应用应答；pair: exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S03 | c2.ua_behavior_conflict | 本批未找到必要材料或来源 | ua: 没有HTTP UA明文；SNI不是UA；protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S04 | c2.dns_encoded_intent | 本批未找到必要材料或来源 | decode: 本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码；decoded_payload: 没有可核验解码链对应明文 |
| S05 | phishing.deception | 本批未找到必要材料或来源 | page: 没有页面正文；host: DNS名及SNI存在，但不是HTTP Host字段；brand_authorization: 没有真实授权域目录 |
| S06 | phishing.credential_action | 本批未找到必要材料或来源 | credential_fields: 没有当前请求中的凭据字段明文；protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S07 | exfil.sensitive_upload | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令；volume: 可以计算已保存报文载荷长度，不能证明整个上传事务体量；content_classification: 没有实际上传内容及敏感分类来源，当前适配不自动生产 |
| S08 | exfil.chunk_sequence | 本批未找到必要材料或来源 | chunk: 没有可核验的分块上传字段、块序号与事务体量；volume: 可以计算已保存报文载荷长度，不能证明整个上传事务体量；transfer_join: 没有跨块/事务的真实传输关联标识 |
| S09 | exploit.payload_intent | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令；parsed_payload: 没有可读请求正文，握手/密文不能当利用载荷 |
| S10 | protocol.response_meaning | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令；protocol_response: 没有与上述请求绑定的可读应用应答；pair: exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S11 | mining.protocol_intent | 本批未找到必要材料或来源 | stratum_request: 未发现真实mining方法和参数；stratum_response: 未发现可关联Stratum应答；pair: exchange有两侧报文，但不是已核验同事务应用请求应答 |
| S12 | c2.domain_lexical/dga_lexical | 现有来源可补齐 | 已有真实来源；R06/R07需上线自动历史链路，S15仍需控制语义预算 |
| S12 | phishing.deception/brand_semantic_impostor | 本批未找到必要材料或来源 | brand: 没有已核验页面品牌或品牌声明；host: DNS名及SNI存在，但不是HTTP Host字段；brand_authorization: 没有真实授权域目录 |
| S13 | payload.decoded_intent/command | 本批未找到必要材料或来源 | decode: 本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码；decoded_payload: 没有可核验解码链对应明文；protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令 |
| S13 | payload.decoded_intent/other | 本批未找到必要材料或来源 | decode: 本批未得到符合语义契约的实际编码链，TLS解密不属于base64解码；decoded_payload: 没有可核验解码链对应明文；operation_context: 没有满足绑定的解码后操作上下文 |
| S14 | review.benign_alternative | 本批未找到必要材料或来源 | protocol_request: 本批没有可供命令/利用意图解释的HTTP或Stratum请求；SSH标识不是命令；asset_role: 有资产登记，但asset_type=ip不代表业务角色；语义适配当前主要依赖授权角色；task_context: 没有授权任务资料 |
| S15 | review.stage_and_gaps | 现有来源可补齐 | 已有真实来源；R06/R07需上线自动历史链路，S15仍需控制语义预算 |
| BT-S01 | botnet.coordination | 本批未找到必要材料或来源 | group_member: 没有已核验群体成员和角色，本批只绑定一个资产 |
| SC01 | c2.role_schedule_conflict | 本批未找到必要材料或来源 | asset_role: 有资产登记，但asset_type=ip不代表业务角色；语义适配当前主要依赖授权角色；business_schedule: 没有业务作息资料，当前输入结构也未自动供给该材料 |
| SC02 | botnet.group_alternative | 本批未找到必要材料或来源 | group_member: 没有已核验群体成员和角色，本批只绑定一个资产 |
| SC03 | phishing.brand_field_conflict | 本批未找到必要材料或来源 | brand: 没有已核验页面品牌或品牌声明；credential_fields: 没有当前请求中的凭据字段明文；brand_authorization: 没有真实授权域目录 |
| R06 | history.activity_association | 现有来源可补齐 | 已有真实来源；R06/R07需上线自动历史链路，S15仍需控制语义预算 |
| R07 | history.alternative_explanation | 现有来源可补齐 | 已有真实来源；R06/R07需上线自动历史链路，S15仍需控制语义预算 |
