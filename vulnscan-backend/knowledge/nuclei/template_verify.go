package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
)

// TemplateIntegrityChecker validates template content for safety before import.
type TemplateIntegrityChecker struct{}

// NewTemplateIntegrityChecker creates a checker.
// The blockUnsigned parameter is retained for API compatibility but no longer blocks code-protocol templates;
// code-protocol safety is enforced at runtime via SignedTemplatesOnly.
func NewTemplateIntegrityChecker(_ bool) *TemplateIntegrityChecker {
	return &TemplateIntegrityChecker{}
}

// dangerousPatterns that suggest potentially malicious template content.
var dangerousPatterns = []string{
	"rm -rf", "mkfs.", "dd if=/dev/zero", ":(){ :|:& };:",
	"wget http", "curl http", "/etc/shadow",
	"nc -e", "bash -i", "python -c 'import socket",
	"powershell -enc", "certutil -urlcache",
}

// CheckContent validates template YAML content for safety.
// Returns an error if the content appears dangerous or invalid.
func (c *TemplateIntegrityChecker) CheckContent(content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("模板内容为空")
	}

	tmpl, err := ParseTemplate(content)
	if err != nil {
		return fmt.Errorf("模板解析失败: %w", err)
	}

	lower := strings.ToLower(string(content))

	hasCode := strings.Contains(lower, "code:") || strings.Contains(lower, "type: code")
	if hasCode {
		slog.Warn("[TemplateCheck] 模板使用 Code 协议，运行时需启用签名验证以确保安全",
			"template_id", tmpl.ID)
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			slog.Warn("[TemplateCheck] 检测到潜在危险模式",
				"template_id", tmpl.ID, "pattern", pattern)
			return fmt.Errorf("模板包含潜在危险命令: %s (template_id=%s)", pattern, tmpl.ID)
		}
	}

	return nil
}

// ContentHash returns a SHA-256 hash of the template content.
func ContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// BuildSignedOnlyOption returns the SDK option for signed-only mode if configured.
func BuildSignedOnlyOption(config map[string]interface{}) []nucleilib.NucleiSDKOptions {
	if boolFromConfig(config, "nuclei_signed_only") {
		return []nucleilib.NucleiSDKOptions{nucleilib.SignedTemplatesOnly()}
	}
	return nil
}
