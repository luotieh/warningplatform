package agent

import (
	"fmt"
	"strings"
)

// EnsureRuntimeCredentials 校验启动前已加载主控签发的 node_uuid 与 secret。
func EnsureRuntimeCredentials(cfg *RuntimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("配置为空")
	}
	secret := strings.TrimSpace(cfg.Secret)
	token := strings.TrimSpace(cfg.Token)
	if secret != "" && token != "" {
		return nil
	}
	credPath := strings.TrimSpace(cfg.CredentialsFile)
	if credPath == "" {
		return fmt.Errorf(`未配置节点凭据：请在 agent.toml 中取消注释并设置 credentials_file，或使用：
  agent run -credentials-file <解密后的 node-agent.credentials.json>
或设置环境变量 AGENT_CREDENTIALS_FILE`)
	}
	return fmt.Errorf("凭据文件 %q 未提供有效的 node_uuid/secret，请确认该文件为 decrypt-credentials 解密后的明文 JSON", credPath)
}

// MaskNodeID 用于日志展示，避免完整 UUID 泄露。
func MaskNodeID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 10 {
		return id
	}
	return id[:8] + "…"
}
