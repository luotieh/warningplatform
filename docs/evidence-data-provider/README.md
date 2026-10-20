# 数据采集层与预处理层

统一入口`PrepareEvidenceFromPlatform`按顺序执行两个独立阶段：

```text
平台事件/资产/冻结快照/原始命中/历史及群体候选/可信补充
  → CollectEvidenceFromPlatform(ctx, reader, eventID, options)
  → EvidenceCollection（原始JSON、查询审计、版本和摘要）
  → PreprocessCollectedEvidence(ctx, collection)
  → PreparedEvidenceBundle + EvidenceSupplyAudit
  → 原有F/S/C执行器
```

- 采集层使用窄只读`EvidenceReader`，支持分页、水位、窗口及行数/字节预算；默认回查30天历史。
- 预处理层不接收数据库接口，可离线重放collection；解析已有报文，核验资产/设备/端点及IOC，生成去重联系、协议观测、群体连接及资产级输入。
- 前两项时间规则缺少窗口证明时采用`default_assumption`；明确读取缺失、截断、解析和绑定失败仍保留。该假设不升级HTTP、Network或群体的已核验完整性。
- SYN与HTTP只在连接身份、会话起始时间及序列关系相符时去重；未匹配SYN保留并按联系类型分别计算。
- 来源、基线、品牌授权及真实生产覆盖仍取决于平台保存的材料。本实现不宣称已达到全部Mock证据覆盖；本地真实归档回放也不等于线上全量历史验收。

## 使用

在`vulnscan-backend`目录执行，输出目录必须尚不存在：

```powershell
# 只采集，不预处理或调用算法
go run ./traffic/cmd/evidence-provider -event synthetic-botnet -fixture ../docs/evidence-data-provider/fixtures/botnet.json -output ./provider-collection -collect-only

# 采集、预处理，再执行现有算法；语义槽位默认关闭
go run ./traffic/cmd/evidence-provider -event synthetic-botnet -fixture ../docs/evidence-data-provider/fixtures/botnet.json -output ./provider-check -execute -semantic disabled

# 本地四份合成Mock基线验收（Stub不代表真实语义核验）
go run ./traffic/cmd/mock-scenarios -scenario all
```

CLI写出`platform-collection.json`、Bundle及查询/字段来源审计。Go调用方可断开数据库后直接调用`PreprocessCollectedEvidence`重放已保存collection。`-dsn-env`可替代`-fixture`，从指定环境变量读取授权测试库DSN；使用只读可重复读事务，不初始化或迁移数据库。没有新增HTTP接口，也未切换生产报告入口。

## 验证与说明

`go test ./... -count=1`、`go vet ./...`、`go build ./...`通过。可选的真实归档测试仅在设置`PROVIDER_TEMPORAL_ARCHIVE`后执行；本地原始归档、生成页面及二进制不属于源码交付。

- [两层职责及collection契约](layer-separation/README.md)：拆分阶段记录。
- [时间证据预处理、窗口策略及SYN修正](temporal-preprocessing/README.md)：当前时间规则行为与实际回放结果。
- [架构](architecture.md)。
- `fixtures/`：四份隔离平台行Fixture；`docs/evidence-pipeline-v2/mock-scenarios/`：对应的独立标准Mock输入及来源登记，供测试和基线执行使用。
