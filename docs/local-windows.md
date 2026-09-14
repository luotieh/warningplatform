# Windows 本地部署（不使用 Docker）

在 `manage_platform` 目录下使用 PowerShell 7 执行命令。

## 运行方式

前端构建到 `vulnscan-backend/frontend/dist`，随后嵌入 Go 可执行文件。
完整服务地址为 `http://127.0.0.1:8090`。MySQL 与 IAM 必须配置可用；
默认使用内存缓存和 noop 消息队列，不要求 Redis、RabbitMQ 或 Docker。
站点监测的 NATS、扫描工具、LLM 等按实际功能需要另行配置。

本次下载的工具位于 `.local/tools`：Node.js 22.22.0、pnpm 10.28.2、Go 1.26.3。
脚本只在当前进程中设置 PATH，不更改系统 Node.js。

## 配置

本地文件 `vulnscan-backend/config.toml` 已从
`scripts/local.config.example.toml` 生成，已被 Git 忽略。
不要直接使用仓库中的 `dev.config.toml`，该文件指向远程开发环境。

需要填写以下字段中的 `REPLACE_ME`：

- `[db]`：本机 MySQL 账号、密码、库名；预先创建独立的 `manage_platform` 数据库，并授予该账号此库的建表和读写权限。
- `[iam]`：可访问的 IAM 地址及该应用的 `client_id`、`client_secret`。
- `[sso]`：本地回调地址已设为 `http://127.0.0.1:8090/callback`，需在 IAM 中注册对应回调；Cookie 密钥已随机生成。
- `[traffic] database_url`：例如 `manage_platform:密码@tcp(127.0.0.1:3306)/manage_platform?parseTime=true&charset=utf8mb4&loc=UTC`。
- `[traffic] internal_api_key`：配置内部接口密钥，与调用方一致。

`VITE_AUTH_MODE=local` 仅表示显示登录表单，账号认证仍然依赖 IAM。
本地部署不会绕过认证，也不会自动创建 IAM 管理员账号。

## 构建与启停

```powershell
./scripts/native.ps1 InstallFrontend
./scripts/native.ps1 BuildFrontend
./scripts/native.ps1 BuildBackend
./scripts/native.ps1 Start
./scripts/native.ps1 Status
./scripts/native.ps1 Stop
```

后端构建会下载 Go 依赖、生成缺失的 Wire 依赖注入代码，再编译到
`.local/bin/manage-platform.exe`。其中以下模块要求能访问公司代码服务：

- `code.yt-security.com/public/core v1.0.3`
- `code.yt-security.com/public/access v0.3.0`
- `code.yt-security.com/public/scanengine v1.0.0`

连接公司网络/VPN，并配置 Git 的访问权限后再构建；不要把访问令牌写入脚本。
脚本为此域名配置当前进程的 `GOPRIVATE`。启动会检查 `/health/ready`；
启动失败时查看 `.local/logs/backend.out.log` 和 `backend.err.log`。
停止命令只操作由脚本记录且进程身份匹配的服务，不修改本机 MySQL 服务。

## 仅预览前端

```powershell
./scripts/native.ps1 Preview
./scripts/native.ps1 StopPreview
```

访问 `http://127.0.0.1:5889`。这是已构建前端的预览；完整登录及业务请求仍需要
8090 端口的后端和 IAM 服务。前端预览可独立停止。

`.local` 中的工具、日志、进程记录，以及本地 `config.toml` 不会提交到 Git。
