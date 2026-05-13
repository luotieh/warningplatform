package nuclei

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParseTemplate(data []byte) (*NucleiTemplate, error) {
	var tmpl NucleiTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("解析Nuclei模板失败: %w", err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("模板缺少ID")
	}
	if tmpl.Info.Name == "" {
		return nil, fmt.Errorf("模板缺少名称")
	}

	return &tmpl, nil
}
