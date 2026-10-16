# 竞态测试

尝试 `CGO_ENABLED=1 go test -race ./evidence ./traffic/internal/service`，未通过编译。当前Windows环境缺少gcc（race-test.log），不能计为竞态测试通过。Docker Linux引擎不可用，未修改180工具链或生产环境。

需要在具备C编译器的隔离Windows或Linux环境运行同一测试并保存输出。普通单测、受控4并发测试和vet不能替代race。
