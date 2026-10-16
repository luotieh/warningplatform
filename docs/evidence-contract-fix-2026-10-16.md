# 证据目录—代码合同一致性修复

本轮修改真实Go后端。基于分支`trafficanalysis-local-fix`、HEAD `c9becc8c11bd719cbf7531785e9bbce8c3402bac`及上一轮未提交修复继续开发，保留原有改动。附件审计的11项偏差在本地对应分支上得到确认；其“24/24/11”分组属于外部静态审计分类，不作为系统状态或生产认证。

交付：相对上一轮交付的26文件增量[patch](evidence-contract-fix-2026-10-16.patch)、[逐项测试和回放JSON](evidence-contract-fix-2026-10-16.json)、[可执行目录导出的82项合同JSON](evidence-contracts-2026-10-16.json)、[合同说明](../vulnscan-backend/evidence/CONTRACTS.md)。增量通过在本地临时比较目录重建上一轮patch获得，没有重置、暂存或提交当前工作区。

## 11项偏差与共同P0

| 项目 | 处理和反例 |
| --- | --- |
| F_FAILED_TO_ACTIVE | 同一IDNA规范问题名先前失败→成功回答IP→同资产设备300秒内真实连接；不同域名、不同子域、其他回答IP、过期连接不成立；来源、时间、端点错绑为missing |
| F_TIME_COORDINATION | Endpoint必须为协议/IP/端口；只计算该端点。空Endpoint/IP单值missing；同IP不同端口或协议不合并 |
| F_INFECTION_CHAIN | 保留兼容ID，显示为“疑似横向传播时序”；验证共同外联端点；一条路径不宣称多B、感染或利用成功 |
| F_CONN_FAIL_RATE | 区分确认失败、确认成功、尝试中、未知；分母只在完整结局集合中成立。SYN_SENT不计失败，单独RST不等于失败，CLOSED不等于成功；缺结局missing并保留分类统计 |
| F_SHARED_ENDPOINT | 统一tcp/udp+规范IP+目的端口；必须对应真实成员资产连接；DNS查询不能补足连接资产数 |
| 群体连接共同P0 | 逐条绑定成员HitIDs、真实命中ID、资产、设备、组、时间、协议/IP/端口；重复SourceID拒绝。所有10条群体规则都运行错绑反例 |
| F_NXDOMAIN_CLUSTER | 正式合同修订为完整查询分母上的NXDOMAIN比例超p99，且≥2失败注册域。保留现有比例基线，不混用计数单位 |
| F_HTTP_SIZE_STABILITY | 只声明HTTP请求体BodyLength的CV与唯一长度比例，去除响应尺寸和未实现z分数表述 |
| F_MULTI_REDIRECT_CHAIN | 更名多次HTTP重定向，声明至少2条验证边，不宣称短链服务 |
| F_TLS_SNI_MISMATCH | 显示SNI与证书名称不符；保留ID兼容，不宣称目的服务身份比较 |
| F_SMALL_PACKET | 显示低应用载荷占比，新增zero_payload_fraction，与small_payload_fraction分别记录；1字节小载荷不会声称零载荷 |
| F_HIST_INFRA_PERSISTENCE | 显示连续跨日多资产IOC关联；不宣称服务存活、钓鱼或直接加分 |

同时收紧DGA词形、有限字符域名近似、子域品牌词、群体分布、首个已保存访问等目录描述；同步C01不执行旧版审核加减分的合同。没有重复审核IOC可信度，没有降低C02/C03/C04阈值。

## 结构化合同和S类边界

59F和23S均提供`feature_claim`、`security_interpretation`、`cannot_prove`、`required_correlations`。这些字段进入F结果、S规划/结果、归一证据、报告输入；未执行项仍是unavailable，不因注册而自动成立。

S结果新增程序赋值的`structure_validation=passed`、`semantic_support=support/contradict/neutral`、`behavior_outcome=not_established`。引用合法、同事务应答和strong均不等于执行成功。缓存重新校验这些字段及合同，拒绝将解释篡改成执行结果。报告归一质量名称改为structure_validated，避免暗示语义已证实；5个解释专用槽位继续不独立计分。

版本：F `evidence-algorithms-0.7`、S `evidence-semantics-0.5`、归一 `evidence-normalization-0.2`、报告 `evidence-report-1.7`。报告继续兼容读取1.4/1.5/1.6历史版本。一期仍只执行5F、S01/S04/S09/S13-command及C01–C07。

## 逐文件变更

以下均相对上一轮交付，完整路径列表和可复核测试名在JSON中。

| 文件（vulnscan-backend下，另行注明除外） | 修改 |
| --- | --- |
| evidence/contracts.go（新） | 四字段合同及弱特征边界，独立合同版本 |
| evidence/catalog.go | 修正名称和实际算法合同；Definitions返回独立合同 |
| evidence/dns_rules.go | 同问题名失败链、实际连接绑定、重复DNS来源防护、网络依赖版本 |
| evidence/group_rules.go | 规范端点、逐连接来源绑定、端点过滤和目标集合身份 |
| evidence/network_rules.go | 连接结局分类、完整性与分母、零载荷统计、重复来源防护 |
| evidence/inputs.go | 新增Transport和OutcomeVerified输入合同 |
| evidence/input_contract.go | 失败激活的网络/命中依赖和连接结局需求 |
| evidence/types.go | F结果携带合同，F版本升版 |
| evidence/engine.go | F结果统一补入实际合同 |
| evidence/semantic_types.go | S合同、结构验证/语义支持/行为结果字段及版本 |
| evidence/semantic_catalog.go | 23S合同；返回副本避免可变切片污染注册表 |
| evidence/semantic_engine.go | 程序补入边界字段；每项任务独立合同切片 |
| evidence/semantic_validation.go | 缓存不能提升行为结果或篡改合同 |
| evidence/normalization.go | 保留82项合同，语义质量明确为结构通过 |
| traffic/internal/service/report_evidence.go | 报告模型输入保存合同与S边界；报告升版和历史读取兼容 |
| evidence/contracts_test.go（新） | 59来源/有效时间反例、70群体错绑反例、DNS/TCP/端点/弱特征边界、69S正反引用测试、82合同完整性及不可变性 |
| evidence/all_rules_test.go | 原DNS阳性夹具纠正同问题名；群体夹具构造真实对应Hit；确认结局显式核验 |
| evidence/negative_rules_test.go | 阴性保留独立真实连接/时间绑定，避免阴性夹具实际变成missing |
| evidence/binding_rules_test.go | 扇出衔接测试同步真实Hit来源，不绕过新绑定 |
| traffic/internal/service/evidence_contract_test.go（新） | 82项合同进入正式报告模型输入的集成测试 |
| traffic/internal/httpapi/report_document_test.go | API当前报告schema断言升级1.7 |
| evidence/CONTRACTS.md（新） | 实际算法、供应方责任、兼容ID和验收边界 |
| evidence/README.md | 更新权威合同/版本/一期范围提示 |
| evidence/RULES.md | 同步目录显示名称和合同修订提示 |
| evidence/SEMANTICS.md | 明确4S正式一期范围及结构通过不等于语义正确 |
| tools/evidence-contract-catalog.go（项目根，新） | 离线导出实际82项注册合同与一期范围，不访问库或模型 |

## 验证命令与结果

模块目录`vulnscan-backend`：

```powershell
go build ./traffic/...
go test ./evidence ./traffic/... -count=1
go vet ./evidence ./traffic/internal/store ./traffic/internal/service
go test ./evidence -json -count=1
go test ./traffic/internal/service -run '^(TestPhaseOneArchivedSnapshot34C01|TestPhaseOneSavedModelResponseReplay|TestReportPromptPreservesFeatureAndSemanticBoundaries)$' -count=1 -v
go run ../tools/evidence-contract-catalog.go ../docs/evidence-contracts-2026-10-16.json
```

项目根目录真实冻结快照回放：

```powershell
./tools/phase1-round2-acceptance.ps1 -OutputPrefix contracts-final-coverage180
git apply --check --reverse docs/evidence-contract-fix-2026-10-16.patch
git diff --check
```

均通过。证据目录已有59项算法阳性和59项不同数值/内容阴性，本轮校正了原有错误阳性夹具，新增59项来源或有效时间反例。23S逐槽位执行support、contradict、伪造引文69分支；缺材料/未核验材料回归继续通过。82行JSON关联具体通过的Go子测试名称。

日志：`.local/contracts-final-acceptance.log`、`.local/contracts-last-tests.log`、`.local/contracts-extra-tests.log`、`.local/contracts-evidence-tests.jsonl`。报告升版时发现API测试写死旧schema，已更新当前版本断言，最终完整回归通过。

## C01–C07回放状态

七份已保存真实冻结快照共13,601条原始命中，逐事件固定原版本及双水位，全部实际生成报告并核对结构化联合结果。当前回放未调用模型、未写生产；新结果使用新前缀，上一轮档案保留。

| 单元 | 本轮执行结果 |
| --- | --- |
| C01 | 快照34离线专项稳定复现85事件/22日历史材料；七快照中的多端点复发按同源去重，observed不能按条数累加分 |
| C02 | 30个完整样本范围有效not_observed；其他93个范围missing（包括样本不足及覆盖/绑定缺失），不混称全部为统计阴性 |
| C03 | 1个真实阳性：ly-75e2c9ed…快照14747、tcp/443，66次独立TCP连接、3自然日、64/66在最佳2小时窗口，10分；其余122个范围missing |
| C04 | 2个完整HTTP范围有效not_observed；其余121个范围missing；8081碎片/未知HTTP候选仍不足以签发有效阴性 |
| C05/C06/C07 | 本轮七快照回放不执行新模型，均保留missing；既有受控HTTP/DNS材料的已保存K2.7响应按当前代码重验并通过联合门控，不标记为新的真实恶意阳性 |

这些是“单元×资产端点/IOC范围”的执行实例，不能解释成独立事件数量。七快照C01的113个observed多为同资产IOC在不同端点展示，计分去重后多数为0贡献，未绕过去重。详细状态、来源、水位和测试证据在JSON与新前缀回放档案中。

## 保留边界

1. 23S模拟模型正反向测试只验收材料与输出合同，尚未进行23槽位全量真实模型语义准确性评价；合法引用可以承载错误解释，这一风险不能由JSON校验消除。
2. 通用一期之外的基线、完整连接生命周期、可信群体、品牌授权、TLS及历史战役资料仍依赖真实供应方，不宣称全部生产可得或已验收。
3. 跨连接浏览器逻辑会话尚无独立身份供应。重定向沿用已核验SessionID限制，不猜测跨连接关联；不把该限制伪装为完整浏览器跳转重建能力。
4. OutcomeVerified是可信生命周期供应方责任，不能由单包SYN/RST或CLOSED推定。缺该来源时通用失败率missing是预期行为。
5. 本轮没有重新抓取180、访问生产数据库、调用远端或本地LLM、修改部署。原四个无关文件SHA256均保持不变，没有提交或清理原有修改。
