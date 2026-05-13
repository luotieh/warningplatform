package nuclei

// PocEntry represents a PoC template loaded from the database,
// carrying both parsed metadata and raw YAML content for Nuclei engine execution.
type PocEntry struct {
	ID         string
	Name       string
	Severity   string
	Tags       string
	RawContent string
}

// NucleiTemplate is used for YAML parsing/validation only.
type NucleiTemplate struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`
}

type TemplateInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Reference   []string `yaml:"reference"`
	Tags        string   `yaml:"tags"`
}
