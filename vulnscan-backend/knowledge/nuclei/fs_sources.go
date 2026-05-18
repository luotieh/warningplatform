package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vulnscan-backend/scan/core"
)

// CollectFilesystemTemplateSources 从任务 config / parameters 读取本地模板与工作流路径（用于镜像目录或官方 nuclei-templates），
// 若存在任一有效路径则 ok=true，此时 NucleiModule 可跳过数据库 PoC 物化。
//
// 支持的键：
//   - nuclei_template_paths: []string 或 []interface{}（文件或目录的绝对/相对路径）
//   - nuclei_template_dir: string（单目录）
//   - nuclei_template_dirs: []string 或 []interface{}
//   - nuclei_workflow_paths / nuclei_workflow_dir / nuclei_workflow_dirs：同上，写入 Nuclei WorkflowSources
//
// 环境变量 VULNSCAN_NUCLEI_EXTRA_TEMPLATE_DIRS：逗号分隔的额外模板目录，在 nuclei_use_env_template_dirs 为 true 时追加（默认 true）。
func CollectFilesystemTemplateSources(config map[string]interface{}) (templates []string, workflows []string, ok bool, err error) {
	if config == nil {
		return nil, nil, false, nil
	}
	seenT := make(map[string]struct{})
	seenW := make(map[string]struct{})

	add := func(dst *[]string, seen map[string]struct{}, p string) error {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("路径解析失败 %q: %w", p, err)
		}
		if _, e := os.Stat(abs); e != nil {
			return fmt.Errorf("模板路径不存在或不可访问 %q: %w", abs, e)
		}
		if _, dup := seen[abs]; dup {
			return nil
		}
		seen[abs] = struct{}{}
		*dst = append(*dst, abs)
		return nil
	}

	appendSlice := func(dst *[]string, seen map[string]struct{}, key string) error {
		for _, s := range configStringSlice(config, key) {
			if err := add(dst, seen, s); err != nil {
				return err
			}
		}
		return nil
	}

	if err := appendSlice(&templates, seenT, "nuclei_template_paths"); err != nil {
		return nil, nil, false, err
	}
	if s := strings.TrimSpace(configString(config, "nuclei_template_dir", "")); s != "" {
		if err := add(&templates, seenT, s); err != nil {
			return nil, nil, false, err
		}
	}
	if err := appendSlice(&templates, seenT, "nuclei_template_dirs"); err != nil {
		return nil, nil, false, err
	}

	if err := appendSlice(&workflows, seenW, "nuclei_workflow_paths"); err != nil {
		return nil, nil, false, err
	}
	if s := strings.TrimSpace(configString(config, "nuclei_workflow_dir", "")); s != "" {
		if err := add(&workflows, seenW, s); err != nil {
			return nil, nil, false, err
		}
	}
	if err := appendSlice(&workflows, seenW, "nuclei_workflow_dirs"); err != nil {
		return nil, nil, false, err
	}

	useEnvDirs := true
	if _, has := config["nuclei_use_env_template_dirs"]; has {
		useEnvDirs = boolFromConfig(config, "nuclei_use_env_template_dirs")
	}
	if useEnvDirs {
		raw := strings.TrimSpace(os.Getenv("VULNSCAN_NUCLEI_EXTRA_TEMPLATE_DIRS"))
		if raw != "" {
			for _, part := range strings.Split(raw, ",") {
				if err := add(&templates, seenT, part); err != nil {
					return nil, nil, false, err
				}
			}
		}
	}

	if len(templates) == 0 && len(workflows) == 0 {
		return nil, nil, false, nil
	}
	return templates, workflows, true, nil
}

// TargetsFromScanLines 将主机名、IP 或带 scheme 的 URL 转为扫描目标（供快捷扫描等复用）。
func TargetsFromScanLines(lines []string) []*core.Target {
	var out []*core.Target
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "://") {
			out = append(out, &core.Target{URL: line})
			continue
		}
		out = append(out, &core.Target{Host: line})
	}
	return out
}
