# 证据目录与代码合同

2026-10-16；`evidence-contracts-1`。正式目录由 `Definitions()` 与 `SemanticDefinitions()` 提供，逐项JSON见项目 `docs/evidence-contracts-2026-10-16.json`。

每项包含 `feature_claim`、`security_interpretation`、`cannot_prove`、`required_correlations`。字段进入F执行结果、S任务和执行结果、归一索引及报告模型输入。F只描述算法测到的特征，S解释可见内容，C按已绑定证据确定性联合计分。注册59F/23S不等于82项生产验收。正式一期仍为5F、4S、C01–C07，未更改C02/C03/C04阈值。

## 来源和统计合同

- `F_FAILED_TO_ACTIVE`：对同一IDNA规范DNS问题名统计先前至少配置次数的NXDOMAIN，再验证NOERROR回答IP与同资产、设备的真实命中连接在300秒内对应。不同子域不合并；失败SourceID重复拒绝。当前统计先前失败次数，不声称连续失败或域名激活原因。
- 群体：每个连接SourceID必须是对应成员的命中ID，时间精确一致，资产、设备和组归属一致，命中端点与连接的协议/IP/目的端口一致；连接来源重复拒绝。`Verified=true`不能绕过这些检查。Hit本身仍须由可信原始报文适配器生成，本模块没有凭空重建主机身份的能力。
- `GroupInput.Endpoint`使用`tcp://IP:port`或`udp://IP:port`，支持IPv6方括号和规范IP表示。空值、IP单值不得执行同端点协同、共享端点、传播时序或跨日端点协同。DNS查询不能充当共享端点连接。
- `F_CONN_FAIL_RATE`：RST/TIMEOUT/REFUSED/FAILED须同时有可信供应方核验的`OutcomeVerified`才能计为确认失败；ESTABLISHED/SUCCEEDED须核验才能计成功。SYN_SENT/SYN_RECEIVED/CONNECTING属于尝试中，CLOSED及其他状态属于未知。单独RST报文不证明建立失败。存在尝试中或未知时保留分类数量并返回missing，禁止只用已终结子集伪装全窗口失败率。
- `OutcomeVerified`应来自可信连接生命周期供应方，不能复制流量正文或客户端标志。常规快照尚无完整生命周期供应时，此通用规则保持missing；不从端口或累计FLOW字段猜测。
- `F_NXDOMAIN_CLUSTER`明确采用NXDOMAIN查询比例基线`nxdomain_rate_p99`，并要求至少两个失败注册域；没有改成计数基线，避免把比例值误作域名数。

## 保留ID，收紧含义

| 兼容ID | 直接特征与边界 |
| --- | --- |
| F_INFECTION_CHAIN | 疑似横向传播时序；A外联→访问B→B外联同端点，一条路径不证明感染、多目标传播或利用成功 |
| F_HTTP_SIZE_STABILITY | 请求体BodyLength的CV和唯一长度比例；没有响应大小或z分数 |
| F_MULTI_REDIRECT_CHAIN | 至少两条验证的HTTP重定向边；未识别短链服务 |
| F_TLS_SNI_MISMATCH | SNI与证书名称不符；未验证目的服务身份 |
| F_SMALL_PACKET | 低应用载荷比例；同时记录零载荷比例，二者不能混用 |
| F_HIST_INFRA_PERSISTENCE | 连续跨日多资产IOC关联；未证明服务存活或钓鱼 |

重定向仍要求可信的RedirectVerified、响应状态、Location和事务边，并沿用同SessionID限制。常规快照只透传session_id，尚无独立浏览器逻辑会话身份供应；因此不会擅自移除限制或拼接跨连接浏览器跳转。需要真实浏览器会话证明时保持材料不足，此能力不属于一期C01–C07。

## S类边界

S结果由程序赋值：`structure_validation=passed`表示来源引用、解码、事务、强度合同通过；`semantic_support`保留模型support/contradict/neutral；`behavior_outcome=not_established`表示本槽位没有确认行为结果。缓存重新核验这些边界，拒绝把其篡改为execution_succeeded。模型无权设置这些字段。

即使strong引用了同事务应答，也不能据此认定执行或利用成功。`explanation_only`的5个槽位只解释上下文。正反向模拟响应测试用于验证执行和引用合同；真实模型的恶意意图准确性须另建有人类标注的独立评估集，不能由程序引用校验代替。

## 验证

既有59项不同算法阳性/阴性测试继续运行；新增59项来源/有效时间反例、所有群体规则逐字段绑定反例、DNS跨域名及连接反例、TCP结局分类、23槽位support/contradict/伪造引用测试、缓存结果边界和报告输入合同测试。跨日规则仍允许有来源的partial阳性，完整性不足不能自动构成阴性。

真实冻结样本回放使用项目已有离线脚本并指定新的输出前缀，保留前轮档案；不写180、不重新抓取、不部署、不调用本地LLM。
