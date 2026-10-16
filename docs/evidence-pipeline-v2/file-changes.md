# 逐文件代码变更

基线 `222c086ac69418539369e3b3b66180f4ccfc4382`，当前分支 `trafficanalysis-local-fix`。实质变更文件 33 个，新增Go文件 14 个；未提交、未推送、未部署。原有未跟踪文件保留。

| 文件 | 说明 |
|---|---|
| `vulnscan-backend/evidence/engine.go` | evaluateFactSafely：单规则panic隔离；原统计规则及阈值保留。 |
| `vulnscan-backend/evidence/normalization.go` | 统一终态、覆盖、模型/输入摘要、去重及风险贡献字段；复用一次槽位目录。 |
| `vulnscan-backend/evidence/phase_one.go` | evidence：限制一期S范围、避免展示去重误伤C谓词；service：拆出computePhaseOneFacts，准备一次后复用。 |
| `vulnscan-backend/evidence/semantic_engine.go` | 分批受控并发、确定顺序合并、取消及单批panic隔离、实际批次指标。 |
| `vulnscan-backend/evidence/semantic_types.go` | 并发配置、每批字节/真实Token可知性/耗时/响应摘要。 |
| `vulnscan-backend/traffic/internal/httpapi/report_document.go` | 报告证据分页处理器，复用鉴权和summary绑定，验证offset/limit。 |
| `vulnscan-backend/traffic/internal/httpapi/report_document_test.go` | HTTP模型fixture引用真实key_evidence；接口鉴权、固定报告版本、明细分页回归。 |
| `vulnscan-backend/traffic/internal/httpapi/server.go` | 注册GET报告证据明细路由。 |
| `vulnscan-backend/traffic/internal/service/agents.go` | 正式报告采用新校验标识及纠错诊断。 |
| `vulnscan-backend/traffic/internal/service/evidence_protocol_input.go` | 协议供应复用统一帧/问题解析结果；保留真实HTTP事务。 |
| `vulnscan-backend/traffic/internal/service/evidence_report_input.go` | 正式报告接入全59F/23S，独立F在S前完成、归一化在C前完成。 |
| `vulnscan-backend/traffic/internal/service/evidence_semantic_input.go` | 复用HTTP正文与DNS解析；S04绑定同一问题来源与F；全槽位顺序。 |
| `vulnscan-backend/traffic/internal/service/evidence_semantic_report.go` | 撤除一期槽位裁剪，版本化模型/输入/并发预算，复用同一预处理输入。 |
| `vulnscan-backend/traffic/internal/service/evidence_snapshot_adapter.go` | 统一解析上下文、计数和预算；流式保留网络及TLS特征。 |
| `vulnscan-backend/traffic/internal/service/evidence_stream.go` | 网络和TLS特征计入保留内存预算；页预算可配置。 |
| `vulnscan-backend/traffic/internal/service/evidence_stream_test.go` | 回归测试适配统一执行及实际报告投影，保留原反例与算法阈值。 |
| `vulnscan-backend/traffic/internal/service/phase_one.go` | evidence：限制一期S范围、避免展示去重误伤C谓词；service：拆出computePhaseOneFacts，准备一次后复用。 |
| `vulnscan-backend/traffic/internal/service/phase_one_coverage_audit_test.go` | 7冻结快照正式链路、最大事件审计存取、报告体积及模型输入预算、交付JSON。 |
| `vulnscan-backend/traffic/internal/service/phase_one_materials.go` | 使用冻结历史来源，历史解析结果复用及实际读取指标；保留时间线去重。 |
| `vulnscan-backend/traffic/internal/service/phase_one_test.go` | 回归测试适配统一执行及实际报告投影，保留原反例与算法阈值。 |
| `vulnscan-backend/traffic/internal/service/report_assessment.go` | 最终模型消费有界概览、证据和确定性C摘要；启用正式引用与边界校验。 |
| `vulnscan-backend/traffic/internal/service/report_assessment_test.go` | 回归测试适配统一执行及实际报告投影，保留原反例与算法阈值。 |
| `vulnscan-backend/traffic/internal/service/report_document.go` | 回读兼容旧报告1.6/1.7及当前2.0，仍校验正文与来源绑定。 |
| `vulnscan-backend/traffic/internal/service/report_essence.go` | 记录投影省略数量及预算；保留完整来源trace在审计中。 |
| `vulnscan-backend/traffic/internal/service/report_evidence.go` | 报告2.0、旧版本兼容、归一化来源/摘要/模型元数据；避免重复构造目录。 |
| `vulnscan-backend/traffic/internal/service/report_history.go` | 保存各历史快照身份、问题和读页诊断；不混淆关联历史与全量流量。 |
| `vulnscan-backend/traffic/internal/service/report_layout.go` | 报告C结果按7类汇总，完整逐实例结果通过审计引用取得。 |
| `vulnscan-backend/traffic/internal/service/report_legacy_numbers_test.go` | 移除重复的test-only实现；同实现已迁入report_evidence_numbers.go。 |
| `vulnscan-backend/traffic/internal/service/report_material.go` | 原始报文核验复用共享帧解码。 |
| `vulnscan-backend/traffic/internal/service/report_narrative.go` | 完整审计附录以82目录状态和审计键定位明细。 |
| `vulnscan-backend/traffic/internal/service/report_observability_test.go` | 回归测试适配统一执行及实际报告投影，保留原反例与算法阈值。 |
| `vulnscan-backend/traffic/internal/service/report_publication.go` | 发布前保证完整审计已保存；报告正文及附录使用有界保存结构。 |
| `vulnscan-backend/traffic/internal/service/services.go` | 增加可注入EvidenceLimits；默认统一流水线注释。 |
| `vulnscan-backend/evidence/semantic_pipeline_test.go` | 受控并发/panic/取消/真实Token门控、82空材料状态和目录导出。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline.go` | 统一正式入口、82目录审计、独立F合并、C实际贡献归一化。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_journal.go` | 压缩分块及完整性清单、来源集合字典化、分页明细、报告有界保存。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_limits.go` | 独立页/当前/历史/特征/超时预算，Services侧可注入。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_metrics.go` | 本次执行读页/字节/JSON/帧/HTTP/DNS次数和分层耗时。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_performance_test.go` | 同一24请求/15冷15热测试可直接在M0基线编译运行。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_projection.go` | 只以完整实例组成模型投影，显式省略数量；概览与C摘要有界。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_snapshot.go` | 历史来源版本冻结与独立时间线分层缓存。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_test.go` | 82状态、模型换版不重读、预处理修订失效、报告引用/数值、完整审计、来源还原与投影。 |
| `vulnscan-backend/traffic/internal/service/evidence_pipeline_time.go` | 7条独立观测相关F延后供应；复用已去重联系点，保留缺失。 |
| `vulnscan-backend/traffic/internal/service/evidence_preprocess_cache.go` | 模型无关预处理缓存，保存HTTP私有字段、校验水位与内容摘要。 |
| `vulnscan-backend/traffic/internal/service/evidence_preprocess_wire.go` | 每命中帧/DNS/协议结果复用，避免重复实际解析。 |
| `vulnscan-backend/traffic/internal/service/report_evidence_numbers.go` | 将原测试专用数字校验迁入实际业务。 |
| `vulnscan-backend/traffic/internal/service/report_pipeline_validation.go` | 拒绝非投影引用、把阴性/缺失当支持、数值篡改及无证据成功断言。 |


## L2合同补修

新增`evidence_prepared.go`、`evidence_prepared_test.go`、`traffic/cmd/evidence-replay/main.go`、冻结Mock JSON；重构`evidence_report_input.go`、`evidence_preprocess_cache.go`、`evidence_semantic_input.go`、`evidence_semantic_report.go`；`phase_one.go`抽取统一策略读取；`evidence_snapshot_adapter.go`新增预制语义材料并更新适配版本；`semantic_types.go`明确tokenizer函数不序列化。具体输入合同、命令和验收边界见`l2-contract-correction.md`。上方文件数量是补修前统计，当前以完整code-changes.patch为准。
