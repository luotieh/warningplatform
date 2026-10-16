# 证据流水线v2交付与验收

真实后端代码已接入：统一快照与预处理 → 59F → 23S前提规划、执行与验证 → 归一化 → C01–C07确定性计分 → 最终研判与报告校验。保留原有算法、82项合同和一期阈值。

本地功能验收通过；真实模型、竞态与生产容量验收尚未全部完成，当前不标记为可部署候选。

修正：此前对M2统一预处理合同的完成声明过强。本次已补上公开可序列化的`PreparedEvidenceBundle`、无Store执行入口、独立Mock JSON及正式/离线一致性测试，见[L2合同补修记录](l2-contract-correction.md)。这不代表真实模型、竞态和容量验收已经通过。

分支：`trafficanalysis-local-fix`。开发前基线：`222c086ac69418539369e3b3b66180f4ccfc4382`。未提交、未推送、未部署。保留原有未跟踪材料；没有重抓冻结样本、写180生产数据或部署。

## 交付索引

- [五层架构、调用链、缓存与配置](architecture.md)
- [逐文件修改说明](file-changes.md)；[真实代码diff](code-changes.patch)
- [82项执行矩阵JSON](execution-matrix.json)；[CSV](execution-matrix.csv)
- [实际目录与输入合同](catalog-input-contracts.json)；[字段和条件映射](input-field-map.json)
- [7快照统计、状态和原因码](real-replay-summary.json)；[C01快照34](c01-snapshot34.json)
- [受控82项执行结果](controlled-execution.json)
- [独立JSON Mock执行结果](prepared-mock-result.json)；[无数据库CLI执行结果](prepared-cli-mock-result.json)
- [真实事件完整审计JSON](real-event-audit.json)；[报告渲染样例](real-event-report.md)
- [模型联调](model-validation.md)；[性能比较](performance.md)
- [验证脚本](verify.ps1)；同目录保存构建、测试、vet、回放和竞态日志。

## 真实样本验收

7个冻结快照共13,601条命中，固定版本、水位、修订水位及成员数量检查通过。每个快照均完成59F、23S目录调度，具有82个终态；scope/task实例可以多于82。C是独立联合层，不计入82目录数。

| 单元 | 结果 |
|---|---|
| C01 | 快照34保持85条历史事件、22日复发；有来源支持的partial阳性不被抹除。14条当前TLS命中未冒充14次通信。 |
| C02 | 30组真实完整输入保持`not_observed`；不足样本保留`missing`，未降低统计阈值。 |
| C03 | 同资产、设备、IOC和端点的66次独立TCP联系，跨3日；64/66位于窗口内，96.97%，`observed`，策略贡献10。没有合并DNS请求。 |
| C04 | 两组真实完整独立请求输入保持`not_observed`，分别168和58次。后者来自140条完整HTTP记录经事务去重，不能将重复记录冒充独立请求。 |
| C05–C07 | 受控正反例、来源/事务/解码链、拒判及已有模型响应回放通过。本轮没有有效的新模型输出，未制造真实语义阳性。 |

最大事件的报告嵌入原约171MB，有界保存后约4.3MB，低于现有16MiB回读上限；完整审计压缩分块保存，已验证最大真实事件的存取和分页还原。最终模型输入由约915KB缩减至约17KB，保留省略数量和审计引用，不删除完整审计中的测量值。

原始材料、覆盖状态、统计值、IOC绑定、实际终态及缺失原因见JSON。原始读取成员齐全不等于每个协议、基线及分析窗口均完整。

## 验证命令

在`vulnscan-backend`运行，以下均通过：

```powershell
go build ./...
go test ./evidence ./traffic/... -count=1
go vet ./evidence ./traffic/...
```

新增全调度、来源绑定、模型版本缓存、压缩审计、分页鉴权、非法引用/数字、批次并发与失败隔离等测试通过。实质修改的Go文件已gofmt，`git diff --check`通过。构建与vet成功日志为空，测试日志保留通过结果。

冻结回放命令：

```powershell
$env:PHASE_ONE_COVERAGE_ARCHIVE='<repo>/.local'
$env:PHASE_ONE_COVERAGE_SUPPLEMENT='<repo>/.local/round2-history-metadata.json'
$env:PHASE_ONE_COVERAGE_OUTPUT_PREFIX='pipeline-v2-coverage180'
go test ./traffic/internal/service -run '^TestPhaseOneCoverageFrozenReportReplay$' -count=1 -v
go test ./traffic/internal/service -run '^TestPhaseOneArchivedSnapshot34C01$' -count=1 -v
```

7快照回放通过，包含C02/C03/C04回归、最大审计存取、报告体积和最终模型输入预算。归一化joint贡献合计等于结构化策略分，F/S自身贡献为0，模型不能覆盖后端分数。

## 未完成项

1. K2.7返回月度额度耗尽，上游403；5次语义批次未取得有效输出。按用户要求停止调用，最终真实模型研判及语义准确性验收跳过。样例报告明确标为渲染验收，不冒称模型结论。
2. 开启CGO尝试竞态测试后，仍因缺少gcc而构建失败，未通过竞态验收。需具备支持的C工具链后执行`go test -race ./evidence ./traffic/internal/service -run "TestSemanticPipeline|TestEvidencePipeline" -count=1`。
3. 受控样本重复帧解析144→24，HTTP解析48→24，读取页数保持不变；整体耗时和分配量增加。实际模型Token、推理性能、真实峰值RSS及生产容量尚未验收。
4. 缺少额外基线、群体、品牌/授权/服务注册材料的规则保留`missing`。82项有终态不代表所有实际材料已经齐全或全部成立。

本轮不部署180。补齐上述验收后再作为部署候选。旧1.4–1.7报告继续兼容读取；回滚代码可保留新增审计记录，新2.0报告不承诺被旧二进制读取，应保留备份和兼容读端，不清空数据库或覆盖生产历史。
