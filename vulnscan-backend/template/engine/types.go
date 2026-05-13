package engine

import "time"

type ScanTemplate struct {
	ID          string          `yaml:"id" json:"id"`
	Name        string          `yaml:"name" json:"name"`
	Description string          `yaml:"description" json:"description"`
	Version     string          `yaml:"version" json:"version"`
	Author      string          `yaml:"author" json:"author"`
	Tags        []string        `yaml:"tags" json:"tags"`
	Params      []TemplateParam `yaml:"params" json:"params"`
	Stages      []TemplateStage `yaml:"stages" json:"stages"`
	CreatedAt   time.Time       `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `yaml:"updated_at" json:"updated_at"`
}

type TemplateParam struct {
	Name        string      `yaml:"name" json:"name"`
	Type        string      `yaml:"type" json:"type"`
	Default     interface{} `yaml:"default" json:"default"`
	Required    bool        `yaml:"required" json:"required"`
	Description string      `yaml:"description" json:"description"`
	Options     []string    `yaml:"options,omitempty" json:"options,omitempty"`
}

type TemplateStage struct {
	Name      string                 `yaml:"name" json:"name"`
	Module    string                 `yaml:"module,omitempty" json:"module,omitempty"`
	Modules   []string               `yaml:"modules,omitempty" json:"modules,omitempty"`
	Parallel  bool                   `yaml:"parallel" json:"parallel"`
	Condition *StageCondition        `yaml:"condition,omitempty" json:"condition,omitempty"`
	Config    map[string]interface{} `yaml:"config" json:"config"`
	DependsOn []string               `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Timeout   string                 `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

func (s TemplateStage) GetModuleIDs() []string {
	if len(s.Modules) > 0 {
		return s.Modules
	}
	if s.Module != "" {
		return []string{s.Module}
	}
	return nil
}

type StageCondition struct {
	PrevStageHasFindings bool   `yaml:"prev_stage_has_findings" json:"prev_stage_has_findings"`
	PrevStageMinTargets  int    `yaml:"prev_stage_min_targets" json:"prev_stage_min_targets"`
	Expression           string `yaml:"expression,omitempty" json:"expression,omitempty"`
}

type TemplateInstance struct {
	TemplateID string
	Params     map[string]interface{}
	Stages     []ResolvedStage
}

type ResolvedStage struct {
	Name      string
	ModuleIDs []string
	Parallel  bool
	Condition *StageCondition
	Config    map[string]interface{}
	DependsOn []string
	Timeout   time.Duration
}
