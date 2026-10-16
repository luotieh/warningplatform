# 逐文件增量

基线为本轮开始时含既有未提交v2改动的本地副本；不是HEAD。清单不包含原有未改动业务文件。

- `vulnscan-backend/evidence/normalization.go`：区分中立/反证/解释/恶意支持；实例身份加入IOC与观测种类。
- `vulnscan-backend/evidence/semantic_states_v21_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/evidence/types.go`：保留独立时间观测种类。
- `vulnscan-backend/evidence/validation_matrix_v21_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_capacity_v21_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_contract_schema.go`：从真实Go结构生成Schema、82项字段映射和导入结构校验。
- `vulnscan-backend/traffic/internal/service/evidence_history_capacity_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_normalized_contract.go`：输出输入摘要、版本、覆盖、诊断和去重来源索引。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline.go`：目录与实例执行统计分开；语义分类汇总；联合实例来源身份。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_journal.go`：发布有界分页索引，保留旧审计格式兼容与完整性校验。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_limits.go`：历史冻结并发默认4且硬限制4。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_metrics.go`：保留微秒阶段耗时。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_pages.go`：每页100实例、源字典裁剪与哈希校验；只解压请求页。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_snapshot.go`：有界历史冻结，保存逐源失败/预算诊断和确定性结果。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_pipeline_time.go`：按资产、IOC和观测种类分别构建独立时间序列。
- `vulnscan-backend/traffic/internal/service/evidence_prepared.go`：扩展现有独立入口：1.1合同、模式、严格导入、覆盖与输出校验。
- `vulnscan-backend/traffic/internal/service/evidence_prepared_contract.go`：校验范围、时间、IOC原始字段、事务、材料引用、覆盖及归一化不变量。
- `vulnscan-backend/traffic/internal/service/evidence_prepared_contract_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_prepared_test.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/evidence_report_input.go`：正式链路接入合同；缓存输入摘要与覆盖，避免热缓存重复读原始数据。
- `vulnscan-backend/traffic/internal/service/evidence_semantic_report.go`：分别记录语义规划和执行/验收耗时。
- `vulnscan-backend/traffic/internal/service/evidence_snapshot_adapter.go`：合同、回归、性能或受控样例验证；详见增量diff。
- `vulnscan-backend/traffic/internal/service/phase_one.go`：联合计算选择同类观测，禁止混合TCP/DNS/HTTP样本。
- `vulnscan-backend/traffic/internal/service/report_evidence.go`：报告来源使用同一实例身份，附加上下文ID避免碰撞。
- `vulnscan-backend/traffic/internal/service/testdata/prepared-controlled-http.json`：合同、回归、性能或受控样例验证；详见增量diff。

文档：v2.1目录为本轮交付；旧v2/input-field-map.json更新为相同的Go生成映射，更新前文件保存在input-field-map-v2-before.json。
