# Evidence Pipeline v2.1交付

本轮已修改真实后端并完成本地增量修复，保留原有五层及59F/23S/C实现。未部署、未写生产库、未提交推送。完整验收仍有外部与性能阻断，不宣称生产可用。

1. 业务变更：Prepared1.1可执行合同、82项Go字段映射、独立无Store执行、正式/独立一致性、解释型S状态、完整归一化合同、实例IOC身份和独立观测种类、历史冻结及审计分页。详见file-changes.md和code-changes.patch（26个后端文件）。
2. 修复明确缺陷：旧映射NodeID与真实device_id不符；neutral/contradict混入missing；不同IOC实例ID冲突；不同通信对象时间序列混用；热缓存摘要与正式/离线不一致；整账本解压分页及串行历史冻结成本。
3. prepared-evidence.example.json可直接Decode→Execute，不需要数据库、原始报文解析或正式报告入口。复用同一执行器，完整结果与正式入口比较通过。
4. 59F受控正/反、缺材料、无效绑定、共同输入边界共295例。没有声称59个数值阈值已逐一穷举。
5. 23S受控结构验收184例；角色/终态69例。82项逐项矩阵将目录、执行、受控与真实验证分列。
6. 真实模型验收0项。本轮按用户要求停止额度不足的K2.7调用，不追问Qwen；Stub不能证明准确率。
7. 7个冻结真实快照回放通过，C01快照34复现85事件22日、10分；C02包含30组完整阴性；C03 TCP66次真实阳性；C04完整HTTP168次真实阴性。C05–C07保持协议/材料/模型诊断，不冒充语义阳性。详见real-replay-summary.json及real-replay.log。
8. 归一化验证来源索引、唯一实例、非C不加分、缺失不加分、去重和总分一致；分数仍是策略证据分，不是校准概率。
9. 构建、单测、vet、Schema外部校验通过。10000实例分页P95明显下降，但整体流水线延迟仍增加，详见performance.md。
10. 上线阻断：真实模型与人工标注、race编译工具链、整体延迟、生产容量/存储/回滚。详见remaining-issues.md及deployment-readiness.md。

主要可核查文件：architecture-delta.md、两份schema、input-field-map.json、execution-validation-matrix.csv、141份mock-fixtures、mock-execution-result.json、test-results.md、各原始测试日志。Schema和字段映射由Go导出，verify_contracts.py验证82项4493字段路径。旧输入设计草案不作为本运行合同。

增量基线：baseline-head.txt仅记录Git锚点；实际diff以本轮开始时含未提交v2工作区的914文件摘要和.local/v21-baseline副本为准，避免将既有改动冒充本轮新增。交付目录保留中间失败日志，最终结果以test-results.md列出的最终日志为准。
