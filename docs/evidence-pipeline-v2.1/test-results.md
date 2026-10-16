# 本地测试结果

Go1.26.8，Windows/amd64。基线与最终工作区相同工具链。

- `go build ./...`：通过，build.log。
- `go vet ./evidence ./traffic/...`：通过，vet.log。
- `go test ./evidence ./traffic/... -count=1 -json`：通过；tests.jsonl，测试级动作汇总 {'run': 1932, 'output': 4001, 'pass': 1911, 'skip': 21}。
- `go test ./traffic/internal/service -run '^TestPreparedEvidenceMockNoStore$|^TestPreparedEvidenceFormalParity$' -count=1 -v`：通过，final-prepared-tests.log；成功路径显式使用stub模式。
- `python docs/evidence-pipeline-v2.1/verify_contracts.py`：通过，82项4493字段路径和两份Schema真实样例。
- 59F×5=295个受控案例；23S×8=184个案例；23S×3=69个角色与终态案例。逐项详见CSV和测试源码。
- 7个冻结真实快照及C01快照34正式报告链路：通过，real-replay.log。

F边界案例为非法快照版本这一共同输入边界，并不表示59项数值阈值均已穷举。S反例包含伪造引用、另一真实事务引用、非法强度和模型失败；Stub不验证模型理解准确率。

中途日志保留了已修复失败：完整账本实例ID冲突、字节切片字段映射、缓存摘要不一致及并行执行时20ms定时测试波动。最终有效结果以上述日志为准。竞态、真实模型与生产容量不在通过项中。

增量补丁经git apply --check与实际应用验证，26个重建文件均与当前代码一致（LF规范化基线）。详见patch-verification.json。
