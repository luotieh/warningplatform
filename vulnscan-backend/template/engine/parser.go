package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseTemplate(data []byte) (*ScanTemplate, error) {
	var tmpl ScanTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("解析模板YAML失败: %w", err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("模板缺少必需字段: id")
	}
	if tmpl.Name == "" {
		return nil, fmt.Errorf("模板缺少必需字段: name")
	}
	if len(tmpl.Stages) == 0 {
		return nil, fmt.Errorf("模板必须包含至少一个阶段")
	}

	for i, stage := range tmpl.Stages {
		if stage.Name == "" {
			return nil, fmt.Errorf("阶段 %d 缺少名称", i)
		}
		if stage.Module == "" && len(stage.Modules) == 0 {
			return nil, fmt.Errorf("阶段 '%s' 缺少模块ID", stage.Name)
		}
	}

	return &tmpl, nil
}

func ParseTemplateFile(path string) (*ScanTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取模板文件失败: %w", err)
	}
	return ParseTemplate(data)
}

func LoadTemplateDir(dir string) ([]*ScanTemplate, error) {
	var templates []*ScanTemplate

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取模板目录失败: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		tmpl, err := ParseTemplateFile(path)
		if err != nil {
			continue
		}
		templates = append(templates, tmpl)
	}

	return templates, nil
}
