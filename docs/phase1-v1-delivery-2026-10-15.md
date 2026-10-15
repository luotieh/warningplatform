# 一期证据库 v1 开发交付与验收（2026-10-15）

已修改真实后端业务代码并接入正式报告准备。C01—C07均有可执行链路；本地构建、traffic全包单测及vet通过。K2.7的HTTP S01/S09/S13-command已全部accepted；DNS真实模型验收被上游7日额度HTTP403阻断，不声明全部端到端验收通过。

## 修改和现有工作保护

当前分支：`trafficanalysis-local-fix`。原有4个已修改文件和首轮Markdown/JSON已逐一SHA256比对保持不变；全部其他已有未跟踪文件保留。未提交、未部署、未修改180生产数据。代码patch只含本轮28个文件，不包含原4个改动。

执行链：`prepareReportInputMode → 精确历史 + 原始帧材料 → 独立时间观测F / HTTP与逐DNS问题F → 四个S槽位 → ExecutePhaseOne / EvaluatePhaseOne → 报告证据、诊断、版本化缓存`。

IOC可信度/审核/有效期由上游负责；本模块只校验原始类型、值、字段及资产端点关系。所有加分为配置策略分，`score_meaning=policy_evidence_points_not_probability`。模型估计未经概率校准。

## 一次事件所需输入材料和本次获取状态

| 单元 | 输入材料 | 实测状态 |
|---|---|---|
| 通用/I | 原始报文、capture_time、src/dst IP及端口、设备、IOC type/value、启用资产登记、固定快照版本和双水位 | 快照34有14条原始命中，14个IP来源绑定通过；已有材料复用，未重抓。 |
| C01 | 同资产地址/设备/IOC真实关系的30日独立历史事件ID、起止时间、实际src/dst、canonical关系、查询覆盖/截断信息 | 85事件/22日；180精确只读计数相同；历史审核/情报有效期不在本模块重复门控。 |
| C02 | 同一IOC/范围的独立通信时间点、观测类型、重传键、历史快照版本/水位、原F规则所需样本及完整性 | 当前14条为TLS报文且无资产主动SYN，独立通信0；不能作为14次通信。其他真实HTTP只有5次请求；受控33次验证阳性。 |
| C03 | 同IOC跨日独立通信、北京时间日期/日内时刻、每个来源快照版本/双水位和完整性 | 真实样本不足；受控3日3个快照（版本3/7/11）通过，保留3个源清单。 |
| C04 | 完整HTTP请求、Host/URL/path/method/请求体长度、RequestID、SourceID、实际事务与完整性；同端点去重后重复序列 | 快照34为TLS不适用；新增真实20条命中含5次独立HTTP请求，未达到规则门槛；受控6请求+6 ACK阳性。 |
| C05 | 完整HTTP请求；S13-command另需编码字段实际值、程序验证的解码链、解码原文及同请求来源 | 受控S01与S13-command均可执行；K2.7对受控HTTP样本联调两槽位均accepted，C05阳性20分。 |
| C06 | 完整请求、真实HTTP body或GET query载荷、事务绑定、逐字引用与S09校验结果 | 受控通过；K2.7 HTTP S09 accepted；与同一载荷C05联合去重后C06为0附加分。 |
| C07 | 实际DNS问题/标签、程序验证编码链、同问题F_DNS_ENCODED_LABEL和S04、字段引用与来源绑定 | 两组真实DNS均不满足编码链；答案中出现IOC不能充当IP通联绑定。受控编码DNS阳性20；真实模型DNS请求403额度耗尽，未通过。 |

## 快照34逐单元结果

事件 `ly-e0eeedcf-1be2-4469-9482-1306573557a3`；版本34；命中水位66209；修订水位126313。当前14条原始报文，独立通信0次；精确历史85事件/22日。C01合计10分。

| 单元 | 状态 | 得分 | 原因 |
|---|---|---:|---|
| C01 | observed | 10 | joint_conditions_met |
| C02 | missing | 0 | insufficient_samples |
| C03 | missing | 0 | insufficient_samples |
| C04 | missing | 0 | missing_input |
| C05 | missing | 0 | accepted_phase_one_semantics_missing |
| C06 | missing | 0 | accepted_phase_one_semantics_missing |
| C07 | missing | 0 | required_material_unavailable |

C01的85条历史是同设备/资产/IOC的传输关系元数据；不继承历史模型结论。C02/C03需要的历史原始帧在本地归档中没有对应历史快照，逐项留下`historical_snapshot_unavailable`。C01正向事实不因这些时间序列缺项被抹掉。程序另有partial阳性单测。

## IOC绑定表（14条原始命中）

以下均为IP IOC `104.21.57.117`，资产ID `asset-0f4ef4d8ee0aa302`、设备 `node-arm-offline-001`、对端TCP/443；字段由实际Ethernet/IP/TCP帧与保存元数据互证。

| 命中ID/来源SourceID | 原始帧字段 | Verified |
|---|---|---|
| hit-fb78c55dcfe33f0b827ecc8cef9affb6546c61c62c5521b2aa074bc2a9e490e0 | ipv4_or_ipv6.src_ip | True |
| hit-7e1642e74b5870ddfdcdf4b0a352a35566d04948201897d8ce98d640350e1202 | ipv4_or_ipv6.dst_ip | True |
| hit-731c3bb4bb45511e61d6ee7ebb6c16ae47293458c22b16b2a1896a0628a6c59a | ipv4_or_ipv6.dst_ip | True |
| hit-242c2985c67e9d8a3585868ec1c594ee6e067f723ef0584b188865779a74dc9c | ipv4_or_ipv6.src_ip | True |
| hit-9a4720fd8a24ec0482d0c0aa5352d7d9f274d26cacc517110dcfb442a4f627db | ipv4_or_ipv6.src_ip | True |
| hit-978e6ffb3cdb5ca5d7eec718c4dfa75150fdf7deade6813bead6299c531b19ae | ipv4_or_ipv6.dst_ip | True |
| hit-4de5ebd1a835c09766416e60d1ac5979d9541d551011ebacdf1a1f570561a1c2 | ipv4_or_ipv6.src_ip | True |
| hit-ecf3f6eaca158a8ecfa3d978c7ac22e129031f1df223420f0df0b2841aded895 | ipv4_or_ipv6.dst_ip | True |
| hit-a7ec5639957e4ccfec59e89b4b75f42f7ad75454cff82fee0819b8afc3eb6229 | ipv4_or_ipv6.src_ip | True |
| hit-c6ed2e2286168f53854e8a350439e5b41b3b4186f365c04bc8a40b6d3e8a38c2 | ipv4_or_ipv6.src_ip | True |
| hit-46531be5a2ddca50bf242298c7a1ddb6ddb192c97e25b80da56719a00065e999 | ipv4_or_ipv6.dst_ip | True |
| hit-c0b7556642144f4082eb0762b67919768d0d7bdf5d8bcde0c268c45ea7847847 | ipv4_or_ipv6.dst_ip | True |
| hit-88ba7aaaef2d5307bbc51fe3854b4aefff8bd4001cec2a5cd4f8c9a27d4953a0 | ipv4_or_ipv6.src_ip | True |
| hit-9bb026d836de3760497dd9105d00418f354983c9ac148e2842338a2bb0527188 | ipv4_or_ipv6.dst_ip | True |

## 其他真实与受控样本

| 单元 | 真实样本状态 | 受控离线链路 |
|---|---|---|
| C01 | 快照34/85事件/22日，observed，10分 | partial阳性、上游不重复审核、错误IOC与跨端口同源去重通过 |
| C02 | 真实HTTP抽样仅5次请求，missing | 33次独立SYN，复用原F_BEACON_JITTER，observed |
| C03 | 真实HTTP抽样日期不足，missing | 3日3个独立快照，observed；重传不增加样本 |
| C04 | 20条真实HTTP命中、5次独立请求，missing | 6个完整同端点请求+6 ACK，仅请求入分母，observed |
| C05 | K2.7 S01/S13-command accepted，observed | 编码HTTP字段→解码→语义→C通过 |
| C06 | K2.7 S09 accepted，observed；与C05同源0附加分 | POST载荷与GET实际查询载荷均通过 |
| C07 | 两个真实DNS事件均不足；模型DNS请求403，无加分 | 实际DNS标签→硬事实→hex解码→S04→C07 observed20 |

真实HTTP事件：`ly-c48e519b-f3be-4df9-aa4b-a96863ef076c`，本轮有界新样本20条。真实DNS事件：`ly-7c77972d-ab18-42fb-b364-7a8d9a41be92`与`ly-e3a5498c-49a4-4778-8837-b3db9b2759da`，各2条。为隔离回放构造MemoryStore投影版本1；不能把该版本当作生产快照版本或声明覆盖全量。

K2.7联调使用受控HTTP/DNS载荷，与180真实抽样回放分开。HTTP一次调用，S01/S09/S13-command全通过逐字引用、来源、强度校验；C05=20，C06同源去重为0，合计20。随后DNS调用遇到HTTP403 `access_terminated_error`（7日额度已耗尽）；集成测试如实失败。所有缓存只写本机MemoryStore；未调用180报告接口或生成生产报告。

## 字段级来源与完整性

| 输出/计算 | 字段来源与校验 |
|---|---|
| IOC绑定 | `ioc_type/ioc_value`对照`raw_packet.packet_hex`解析得到的src/dst、HTTP Host/URL、DNS question或TLS ClientHello SNI；不是描述或情报推荐值 |
| 资产/端点 | 启用资产登记address/ID、实际src/dst和端口、device_id；DNS答案中的IP不自动成为通信远端 |
| C01历史 | events的canonical身份、first/last时间、device_id、ioc和src/dst；参数化AND精确关系，排除当前事件及源事件，窗口左闭右开30日 |
| C02/C03 | 原始TCP SYN且非ACK、完整HTTP请求或实际DNS问题；hash去重，不使用packets/flows计数代替通信 |
| HTTP重复 | 完整报文长度、Content-Length与实际解析、Host/path/method、RequestID；不完整请求不能构造完整阴性分母；保存原始请求和事务引用 |
| S01/S09/S13 | 同一请求的原文、真实body/query、解码材料及事务；逐字quote与材料/事实引用齐全、强度合法才接受 |
| C07 | 同一个DNS问题的F、编码标签、可复核解码链及S04 source IDs交集；禁止用另一个DNS问题的F补足 |
| 缓存 | 一期/适配器/规则版本、策略版本和分数、当前及各历史快照版本与水位、材料、F/S身份；命中后重新验证C分数 |

## 逐文件修改说明

| 文件 | 修改 |
|---|---|
| `tools/phase1-acceptance.ps1` | 新增可重跑离线构建、traffic全包单测、vet和可选localhost模型联调入口；默认禁止网络模型调用并恢复环境变量。 |
| `vulnscan-backend/evidence/http_rules.go` | HTTP重复统计排除不完整请求，按稳定RequestID去重，复用原端点重复算法。 |
| `vulnscan-backend/evidence/inputs.go` | HTTP记录保留请求ID和完整请求/请求体；算法公共JSON继续隐藏敏感原文。 |
| `vulnscan-backend/evidence/phase_one.go` | 新增一期C注册、原始IOC绑定结构、按IOC/范围联合门控、配置策略分、时间/载荷/历史同源去重；逐任务验证被接受的S结果。 |
| `vulnscan-backend/evidence/phase_one_test.go` | 覆盖partial历史阳性、IOC不混用、同时间族去重、同历史跨端口不重复加分。 |
| `vulnscan-backend/evidence/semantic_engine.go` | 将后端要求的逐字引用材料ID显式送给模型；保留原有引用校验门槛。 |
| `vulnscan-backend/evidence/types.go` | F结果增加IOC类型和值，防止同端点不同IOC混合联合。 |
| `vulnscan-backend/traffic/cmd/evidence-check/main.go` | 无数据库目录命令增加一期C/F/S注册与分值策略；事件核验复用正式链路。 |
| `vulnscan-backend/traffic/internal/config/report.go` | 增加TOML及环境变量的一期分值、策略版本和总分上限。 |
| `vulnscan-backend/traffic/internal/service/evidence_protocol_input.go` | 完整HTTP请求、请求体、稳定请求ID与实际TCP序号供应，保留真实事务绑定限制。 |
| `vulnscan-backend/traffic/internal/service/evidence_report_input.go` | prepareReportInputMode正式接入F→S→C；诊断和F缓存指向重算后的独立通信结果，写入报告证据。 |
| `vulnscan-backend/traffic/internal/service/evidence_semantic_input.go` | DNS逐问题事实与编码链、HTTP完整字段值解码、GET实际查询载荷；禁止TLS密文生成HTTP/DNS语义。 |
| `vulnscan-backend/traffic/internal/service/evidence_semantic_report.go` | 只调度S01/S04/S09/S13-command；缓存保留逐问题事实，避免重载时误用聚合DNS事实。 |
| `vulnscan-backend/traffic/internal/service/evidence_semantic_report_test.go` | 原全语义注册表回归夹具显式选择LegacyReportEvidence，保留原断言。 |
| `vulnscan-backend/traffic/internal/service/evidence_snapshot_adapter.go` | 一次扫描收集一期原始材料，HTTP完整性分母改为真实请求候选，版本升级避免复用旧材料。 |
| `vulnscan-backend/traffic/internal/service/evidence_snapshot_adapter_test.go` | 原全注册表回归夹具显式选择LegacyReportEvidence，保留原断言。 |
| `vulnscan-backend/traffic/internal/service/evidence_validation.go` | 只读核验统计精确历史查询次数，沿用正式准备链路输出一期结果。 |
| `vulnscan-backend/traffic/internal/service/phase_one.go` | 新增Services.ExecutePhaseOne执行入口，串接精确历史、独立时间序列F与C，版本化缓存并重算验证缓存分数。 |
| `vulnscan-backend/traffic/internal/service/phase_one_facts.go` | 按资产/设备/端点/IOC供应历史与HTTP事实，逐个DNS问题构造硬事实，保留partial历史阳性。 |
| `vulnscan-backend/traffic/internal/service/phase_one_materials.go` | 新增真实以太帧IOC字段校验、独立SYN/完整HTTP/DNS观测、跨快照版本/水位冻结、重传去重与预算诊断。HTTP请求与SYN不混为两次通信。 |
| `vulnscan-backend/traffic/internal/service/phase_one_test.go` | 真实快照34/85历史回放、其他真实HTTP/DNS、受控C01-C07、只读、跨快照、GET载荷、缓存篡改及可选K2.7集成。 |
| `vulnscan-backend/traffic/internal/service/report_assessment.go` | 正式报告模型输入包含后端C结果，并明确策略分和模型判断均非已校准概率。 |
| `vulnscan-backend/traffic/internal/service/report_evidence.go` | 报告不可变证据包增加完整一期结果、材料和缓存标识。 |
| `vulnscan-backend/traffic/internal/service/report_history.go` | 正式报告启用30日精确历史、201行分页、5000事件/4MiB预算与覆盖诊断，兼容旧宽查询。 |
| `vulnscan-backend/traffic/internal/service/report_layout.go` | 正式五段报告展示后端C结果和策略分，模型百分数明确标为未经校准。 |
| `vulnscan-backend/traffic/internal/service/services.go` | 增加一期分值策略覆盖与显式LegacyReportEvidence兼容配置，默认一期。 |
| `vulnscan-backend/traffic/internal/store/history.go` | 新增资产地址AND设备AND实际IOC关系查询；内存与SQL精确匹配一致，参数化游标分页，IP型排除DNS答案冒充通信。 |
| `vulnscan-backend/traffic/internal/store/phase_one_history_test.go` | 覆盖260条候选中的精确关系、错误设备、DNS答案、分页及SQL参数绑定。 |

## 测试命令与结果

从`vulnscan-backend`目录执行：

```powershell
go build ./traffic/...
go test ./evidence ./traffic/... -count=1
go vet ./evidence ./traffic/internal/store ./traffic/internal/service
go run ./traffic/cmd/evidence-check --catalog --output ../.local/phase1-v1-catalog.json
```

以上均通过；`git diff --check`通过。离线入口（仓库根目录）：

```powershell
./tools/phase1-acceptance.ps1
# 可选模型联调：先启动已授权的localhost代理，再执行
./tools/phase1-acceptance.ps1 -ModelEndpoint http://127.0.0.1:19146/v1
```

默认不调用模型、不访问180，真实归档缺失会明确报错；可选真实HTTP/DNS归档缺失的Go测试会skip，不能当作真实样本已验收。模型测试要求HTTP C05与DNS C07均阳性；本次DNS403导致此命令失败，离线命令最终退出0。

证据：`.local/phase1-v1-offline-final.log`、`phase1-v1-full-tests.log`、`phase1-v1-vet.log`、`phase1-v1-model.log/json`、`phase1-v1-real-samples.json`、`phase1-v1-snapshot34.json`、`phase1-v1-180-verify.json`、`phase1-v1-180-final.json`、`phase1-v1-preservation.json`。

## 配置示例

```toml
[traffic]
phase_one_policy_version = "phase1-score-v1"
phase_one_max_score = 100
phase_one_points = { C01=10, C02=15, C03=10, C04=15, C05=20, C06=20, C07=20 }
```

也支持`PHASE_ONE_POINTS`（JSON对象）、`PHASE_ONE_POLICY_VERSION`、`PHASE_ONE_MAX_SCORE`。自定义分值必须提供版本并完整覆盖七个单元；分值更改使C缓存失效。

## 仍未完成/部署边界

- K2.7 DNS实际模型联调因上游7日额度耗尽HTTP403未通过；受控离线链路通过。
- 其他真实HTTP/DNS样本仅为本轮有界只读抽样，在MemoryStore投影版本1回放，不是生产快照版本1或全量覆盖证明；真实C02/C03阳性材料仍不足。
- 无TCP流重组、跨报文HTTP合并、IP分片重组；不完整材料保持缺失。跨快照100个/20000条/16MiB/30秒，历史5000事件/4MiB，超预算有诊断。
- PCAP代理连通性问题未修复，沿用首轮已保存诊断，不影响本轮已存原始帧执行；没有重新下载PCAP。
- 尚未生产部署或在180运行新二进制。180只做SELECT、配置读取及用户授权模型推理；无本地LLM。

最终180只读核验时间：`2026-10-15T09:31:07.452849+00:00`；快照34 SHA256仍为`bbde0b9277c6bea1e9833a02be3db2612726b6e8371839fc6f90244485536298`，与本轮此前只读结果一致。无原始命中重复抓取、无部署、无生产缓存/数据库写入。
