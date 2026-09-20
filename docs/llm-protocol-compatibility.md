# 流量分析模型接口兼容

健康检查、表单对话测试、工程师对话和自动报告统一使用模型协议适配器。

## 配置

- 常规服务地址填写 `http://host:port/v1`，优先请求 `/v1/chat/completions`。现有 k3、Qwen 等兼容服务保持原调用方式。
- 仅当上游明确拒绝 `/chat/completions` 协议时，自动切换同一服务的 `/responses`，继续使用相同模型、密钥、系统提示和证据输入。
- 可直接填写 `http://host:port/v1/responses`，跳过协议协商。模型列表探测仍请求 `/v1/models`。
- 支持填写完整 `/v1/chat/completions` 地址，避免重复追加路径。
- 鉴权失败、余额不足、限流、超时和普通 5xx 不触发协议切换，也不自动重发生成请求。

## 返回与取消

- Chat Completions 使用 `messages`、`max_tokens`，读取 `choices[].message.content`。
- Responses 使用 `instructions`、`input`、`max_output_tokens`、`store=false`；请求流式输出，兼容 SSE 和完整 JSON 返回。
- Responses 必须返回完成状态及助手的 `output_text`。推理、拒绝、未完成结果和缺少完成事件的断流不作为报告。
- Chat Completions 的 token 截断、空正文和未正常结束结果同样返回错误。
- 重试共享总超时与取消上下文；用户停止操作会取消上游请求。
- 报告输出预算仍为 6000 tokens；测试为 1024 tokens。输入和输出都必须满足部署服务的上下文上限。

## 本地 Qwen

是否可接入取决于推理服务提供的接口，与模型名称、参数规模不是同一回事。提供兼容 `/v1/chat/completions` 的 vLLM、SGLang、Ollama 等服务可按常规服务地址配置，模型名称必须与服务实际发布的名称一致。Ollama 原生 `/api/chat`、仅工具调用、图像及音频接口不在本适配范围内。

“协议支持”不代表已经验证特定模型的服务可用性或报告质量。应通过实际地址测试鉴权、最终正文、上下文容量和生成时延。

## 验证

`go test ./traffic/... -count=1`

测试覆盖原有 Chat 请求、三个调用入口的协议切换、完整地址归一化、Responses JSON/SSE、系统提示及证据传递、输出预算、空回答/截断/拒绝/断流、取消请求，以及错误时不进行无条件重试。

协议参考：https://developers.openai.com/api/reference/resources/responses/methods/create
