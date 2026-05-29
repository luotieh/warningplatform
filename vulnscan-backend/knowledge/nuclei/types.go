package nuclei

// PocEntry represents a PoC template loaded from the database,
// carrying both parsed metadata and raw YAML content for Nuclei engine execution.
type PocEntry struct {
	ID            string
	Name          string
	Severity      string
	Tags          string
	Product       string
	Vendor        string
	AffectedRange string
	RawContent    string
}

// NucleiTemplate is used for YAML parsing/validation only.
type NucleiTemplate struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`
}

type TemplateInfo struct {
	Name           string            `yaml:"name"`
	Author         string            `yaml:"author"`
	Severity       string            `yaml:"severity"`
	Description    string            `yaml:"description"`
	Reference      []string          `yaml:"reference"`
	Tags           string            `yaml:"tags"`
	Classification *TemplateClassify `yaml:"classification,omitempty"`
	Metadata       map[string]any    `yaml:"metadata,omitempty"`
}

type TemplateClassify struct {
	CVEID     any     `yaml:"cve-id,omitempty"`
	CWEID     any     `yaml:"cwe-id,omitempty"`
	CVSSScore float64 `yaml:"cvss-score,omitempty"`
	CPE       string  `yaml:"cpe,omitempty"`
}

// ExtractProduct extracts the product name from template metadata, tags, or ID heuristics.
func (t *NucleiTemplate) ExtractProduct() string {
	if t.Info.Metadata != nil {
		if p, ok := t.Info.Metadata["product"].(string); ok && p != "" {
			return p
		}
		if p, ok := t.Info.Metadata["product-name"].(string); ok && p != "" {
			return p
		}
	}
	return ""
}

// ExtractVendor extracts the vendor from template metadata.
func (t *NucleiTemplate) ExtractVendor() string {
	if t.Info.Metadata != nil {
		if v, ok := t.Info.Metadata["vendor"].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ExtractAffectedRange returns the affected version range from metadata.
func (t *NucleiTemplate) ExtractAffectedRange() string {
	if t.Info.Metadata == nil {
		return ""
	}
	for _, key := range []string{"affected_range", "affected-range", "affected-versions", "version-range"} {
		if v, ok := t.Info.Metadata[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ExtractCPE returns the CPE string from classification or metadata.
func (t *NucleiTemplate) ExtractCPE() string {
	if t.Info.Classification != nil && t.Info.Classification.CPE != "" {
		return t.Info.Classification.CPE
	}
	if t.Info.Metadata != nil {
		if c, ok := t.Info.Metadata["cpe"].(string); ok && c != "" {
			return c
		}
	}
	return ""
}
