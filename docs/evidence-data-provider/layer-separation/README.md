# Provider采集层与预处理层拆分

统一入口`PrepareEvidenceFromPlatform`保留，内部顺序为：

```text
CollectEvidenceFromPlatform(ctx, reader, eventID, options)
    → EvidenceCollection
PreprocessCollectedEvidence(ctx, collection)
    → PreparedEvidenceBundle + EvidenceSupplyAudit
```

| 模块 | 职责 | 边界 |
|---|---|---|
| `evidence_provider_collection.go` | 读取事件、资产、当前与群体原始命中、历史候选及来源快照、来源登记和补充记录；执行查询预算与分页检查 | 唯一持有EvidenceReader的阶段；不生成Bundle、contacts或算法判定 |
| `evidence_collection.go` | 中间数据、版本、摘要校验、原始JSON保存、查询路由字段提取 | 保留完整原始材料；IOC匹配只用于候选查询，不声明完整事务或独立联系 |
| `evidence_provider_preprocess.go` | 校验来源与补充资料，关联历史，合并群体和资产输入，组装语义材料、Bundle及字段审计 | 不接收数据库接口或API客户端；可离线重放，不修改传入collection |
| `evidence_provider_assembly.go` | 确定性协议字段映射、历史筛选、群体组装 | 已移除群体查询；历史审计的快照读取也移至采集层 |
| `evidence_provider.go` | 公共选项、审计类型及原调用入口 | 对现有调用方保持统一入口 |

`EvidenceCollection`包含源记录、快照水位、查询窗口、候选及其可用性、上下文原记录、执行配置和查询审计。当前及群体命中的`raw`在JSON中按base64字节保存，避免RawMessage序列化改变空白/转义、破坏原始字节统计。摘要用于发现意外改动，不是来源认证。

CLI默认额外输出`platform-collection.json`，原有Bundle/执行输出保持。新增`-collect-only`只保存采集结果及查询审计，不执行预处理或算法；不能与`-execute`或`-compare-snapshot`同时使用。

本次完成职责拆分，保留既有算法输入行为。原始`raw_packet`、`exchange`在采集结果中保留；当前预处理仍使用原有应用摘要映射，尚未接通完整报文解析及contacts生成。该能力应继续在预处理层实现，不能把本次重构当作Mock覆盖提升。

## 验证

- 新增测试：平台断开后的离线预处理、含群体与历史的序列化重放、原始JSON及大整数保留、输入/输出隔离、上下文校验归属、篡改和取消处理。
- 原Provider与差分修复测试继续通过。补充资料测试改为在预处理阶段确认拒绝，采集阶段只保留原记录。
- 后端`go test ./... -count=1`通过。
- 四场景重构前后比较Bundle、归一化执行结果与覆盖证明。只排除独立CLI初始化产生的资产/事件时间、相应Bundle摘要，以及执行计时和缓存键；完整结果见`regression-validation.json`。

回归验证命令（在仓库根目录）：

```powershell
python docs/evidence-data-provider/layer-separation/verify_regression.py .local/provider-layer-split --output docs/evidence-data-provider/layer-separation/regression-validation.json
```

所有验证使用本地隔离数据和受控Stub，没有连接生产数据库或真实模型。
