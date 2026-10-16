# L2合同遗漏与补修（2026-10-16）

此前把内部共享结构及压缩缓存当作统一预处理合同完成，判断过强：`SnapshotEvidenceInput`直接JSON会省略Request与语义观测，历史时间线仍在F之后展开，语义规划阶段仍解析载荷和解码链。原交付不能据此宣称M2完整验收。

本次在真实后端修复：

- `PreparedEvidenceBundle`：公开版本化、可序列化的L2/L3边界；携带事件、快照、水位、资产、标准输入、历史、来源诊断、F/S/C配置及内容摘要。
- `EvidencePreparedInputs`：复用既有Request/Input/DNS/HTTP/TLS/Network/History/Groups；附带HTTP原文/正文、平台历史、语义观测和提前验证的语义材料。不会通过直接JSON丢失原有私有字段。
- `loadPipelinePrepared`：在L2完成跨快照独立时间线和语义载荷/解码链材料；L3仅绑定实际F结果、规划S任务及验收模型结果。S04仍严格绑定同一个DNS问题来源。
- `executePreparedPipeline`：正式报告与无Store离线入口共用一个业务执行函数；继续使用原Engine/SemanticEngine/Normalize/EvaluatePhaseOne。没有另建Mock算法。
- `PrepareEvidenceBundle`：使用正式采集与预处理，读取后输出独立输入；不执行模型、不写记录。
- `ExecutePreparedEvidence`：不构造Store、不连接数据库、不访问环境模型；只接受显式注入的语义模型。nil模型只规划，不伪造已执行。
- `EncodePreparedEvidence`/`DecodePreparedEvidence`：校验schema、摘要、事件与快照、当前/历史来源水位、规则目录和预处理边界；禁止携带预填F/S判定。JSON输入上限64MiB，超出明确报错；该限制不等于正式快照读取量或进程RSS上限。

版本：`prepared-evidence-bundle-1.0`、`evidence-preprocess-2.1`、`report-snapshot-adapter-2.1`。旧预处理与F缓存按版本失效，原报告读取兼容逻辑保持。

独立Mock输入：`vulnscan-backend/traffic/internal/service/testdata/prepared-controlled-http.json`。这是受控HTTP数据，经正式预处理产生的冻结输入，不能标为真实阳性。

```powershell
# 在vulnscan-backend运行；输出路径必须尚不存在。
go run ./traffic/cmd/evidence-replay `
  -input traffic/internal/service/testdata/prepared-controlled-http.json `
  -output prepared-replay-result.json `
  -mock-semantics

go test ./traffic/internal/service -run '^TestPreparedEvidence' -count=1 -v
```

CLI使用受控中立语义响应，输出明确标注`real_model_executed=false`；不加`-mock-semantics`则仅规划S任务。`prepared-cli-mock-result.json`是本次实际CLI执行输出，`prepared-mock-result.json`是测试中的受控支持响应执行输出，两者均非真实模型结论。

已验证：独立JSON→59F→23S规划/Mock结构验收→归一化→C；正式与离线的F结果、S验收结果、C结果、82目录终态一致；输入不被执行过程修改；重复执行归一化结果稳定；非法模型响应不会抹除F；水位/来源/目录/预填判定反例被拒绝；取消正确传播。

未将这些测试计为真实模型准确性或完整任务验收。K2.7额度、竞态工具链、峰值RSS与容量验收仍沿用原未完成项；旧性能数据属于补修前版本，不能代替本版本性能验收。没有部署180、写生产数据或重新抓取远端原始材料。

本次补修后验证：构建、相关模块全量单测、vet通过；7个保存的真实快照及快照34 C01回归通过（58.066s）。实际命令与状态见`l2-contract-verification.json`，新回放结果见`l2-contract-real-replay.json`。未重新抓取180。
