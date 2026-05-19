package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

const runtimeConfigTOMLHeader = `# Vulnscan 节点 Agent 配置文件（TOML）
# 加载顺序：本文件 → 环境变量 → 命令行参数 → credentials_file
# 启动：vulnscan-agent run -config agent.toml
`

// DefaultConfigFileName 为 config init 默认输出文件名。
const DefaultConfigFileName = "agent.toml"

// RuntimeConfigTOMLTemplate 返回带注释的默认配置模板正文。
func RuntimeConfigTOMLTemplate() string {
	cfg := DefaultRuntimeConfig()
	body, err := toml.Marshal(cfg)
	if err != nil {
		// 不应失败；回退硬编码
		return runtimeConfigTOMLHeader + `
master_url = "http://127.0.0.1:8080/api"
max_concurrent = 0
task_timeout = "10m"
heartbeat_interval = "10s"
log_level = "info"
`
	}
	var b strings.Builder
	b.WriteString(runtimeConfigTOMLHeader)
	b.WriteString(`
# 主控 API 根地址（须含 /api 前缀，且可访问 /api/node-api/health）
`)
	b.Write(body)
	b.WriteString(`
# 入网后由主控分配（也可使用 credentials_file，见下）
# token = ""
# secret = ""
# topology = "master_public_node_private"

# decrypt-credentials 生成的凭证（推荐生产环境使用）
# credentials_file = "./node-agent.credentials.json"
`)
	return b.String()
}

// WriteRuntimeConfigTemplate 生成 TOML 配置文件。
func WriteRuntimeConfigTemplate(path string, overwrite bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultConfigFileName
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("配置文件已存在: %s（使用 -force 覆盖）", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建目录: %w", err)
		}
	}
	content := RuntimeConfigTOMLTemplate()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	return nil
}

func unmarshalRuntimeConfigFile(path string, b []byte, cfg *RuntimeConfig) error {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return unmarshalJSONRuntimeConfig(b, cfg)
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return fmt.Errorf("解析 YAML: %w", err)
		}
		return nil
	case ".toml", "":
		if err := toml.Unmarshal(b, cfg); err != nil {
			return fmt.Errorf("解析 TOML: %w", err)
		}
		return nil
	default:
		// 未知扩展名时依次尝试 TOML、YAML
		if err := toml.Unmarshal(b, cfg); err == nil {
			return nil
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return fmt.Errorf("无法解析配置文件（支持 .toml / .yaml / .json）: %w", err)
		}
		return nil
	}
}
