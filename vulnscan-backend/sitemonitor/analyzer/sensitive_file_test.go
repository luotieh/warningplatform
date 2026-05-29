package analyzer

import (
	"testing"
)

func TestClassifySensitiveFileHit(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		bodyLen  int
		body     string
		expected string
	}{
		{"200 with content", 200, 100, "DB_PASSWORD=secret123", "content_exposed"},
		{"200 empty body", 200, 0, "", ""},
		{"403 forbidden", 403, 0, "", "auth_required"},
		{"401 unauthorized", 401, 0, "", "auth_required"},
		{"404 not found", 404, 0, "", ""},
		{"200 WAF block", 200, 50, "Access Denied by Firewall. Request blocked by WAF policy.", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySensitiveFileHit(tt.status, tt.bodyLen, tt.body)
			if got != tt.expected {
				t.Errorf("classifySensitiveFileHit(%d, %d, ...) = %q, want %q", tt.status, tt.bodyLen, got, tt.expected)
			}
		})
	}
}

func TestIsDirectoryListing(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"Apache dir listing", `<html><head><title>Index of /backup</title></head><body><pre>Parent Directory</pre></body></html>`, true},
		{"Normal page", `<html><head><title>Home</title></head><body>Welcome</body></html>`, false},
		{"Nginx autoindex", `<html><head><title>Index of /</title></head><body><pre><a href="file1.txt">file1.txt</a> last modified  2024 size 1234</pre></body></html>`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDirectoryListing(tt.body)
			if got != tt.expected {
				t.Errorf("isDirectoryListing(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestClassifyContentFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		path     string
		expected string
	}{
		{"AWS key in env", "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "/.env", "云凭证"},
		{"Git HEAD", "ref: refs/heads/main", "/.git/HEAD", "Git HEAD"},
		{"Git config", "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]", "/.git/config", "Git配置"},
		{"PHP info", "phpinfo()\nPHP Version 8.1.0", "/info.php", "PHP信息泄露"},
		{"DB password", "DB_PASSWORD=mypassword123", "/.env", "数据库凭证"},
		{"Private key", "-----BEGIN RSA PRIVATE KEY-----", "/key.pem", "证书/密钥"},
		{"WordPress config", "define('DB_NAME', 'wordpress')", "/wp-config.php.bak", "WordPress数据库"},
		{"Spring datasource", "spring.datasource.url=jdbc:mysql://localhost/db", "/application.properties", "Spring数据源"},
		{"SQL dump", "CREATE TABLE users (\n  id INT PRIMARY KEY\n);\nINSERT INTO users VALUES (1, 'admin');", "/dump.sql", "SQL导出"},
		{"Unknown .env", "APP_NAME=MyApp\nAPP_DEBUG=true", "/.env", "环境变量"},
		{"Slack token", "SLACK_TOKEN=xoxb-123456-abcdef", "/config.yml", "Slack凭证"},
		{"GitHub token", "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", "/.env", "GitHub Token"},
		{"JDBC connection", "jdbc:mysql://db.example.com:3306/prod", "/application.yml", "JDBC连接串"},
		{"Normal HTML", "<html><body>Hello World</body></html>", "/index.html", ""},
		{"Empty body env path", "", "/.env", "环境变量"},
		{"Backup file path", "some content", "/config.php.bak", "备份文件"},
		{"Log file path", "2024-01-01 Error: something failed", "/app.log", "日志文件"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyContentFingerprint(tt.body, tt.path)
			if got != tt.expected {
				t.Errorf("classifyContentFingerprint(%q, %q) = %q, want %q", tt.name, tt.path, got, tt.expected)
			}
		})
	}
}

func TestIsWAFBlockPage(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"WAF block", "Access Denied. Request blocked by WAF security policy.", true},
		{"Firewall block", "Your request has been denied by the firewall. Access denied.", true},
		{"Normal page", "<html><body>Hello World</body></html>", false},
		{"Long page with WAF word", "This is a very long page... " + string(make([]byte, 2100)) + " waf firewall", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWAFBlockPage(tt.body)
			if got != tt.expected {
				t.Errorf("isWAFBlockPage(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestDefaultProbePaths(t *testing.T) {
	a := &SensitiveFileAnalyzer{rules: &mockRuleAccessor{}}
	paths := a.defaultProbePaths()
	if len(paths) == 0 {
		t.Fatal("defaultProbePaths returned empty")
	}

	pathSet := make(map[string]bool)
	for _, p := range paths {
		if pathSet[p.Path] {
			t.Errorf("duplicate path: %s", p.Path)
		}
		pathSet[p.Path] = true

		if p.Path == "" {
			t.Error("empty path found")
		}
		if p.Mark == "" {
			t.Errorf("path %s has empty mark", p.Path)
		}
		if p.Risk == "" {
			t.Errorf("path %s has empty risk", p.Path)
		}
		validRisks := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
		if !validRisks[p.Risk] {
			t.Errorf("path %s has invalid risk: %s", p.Path, p.Risk)
		}
	}
	t.Logf("defaultProbePaths: %d unique paths", len(paths))

	criticalPaths := []string{"/.env", "/.git/HEAD", "/.git/config"}
	for _, cp := range criticalPaths {
		if !pathSet[cp] {
			t.Errorf("expected critical path %s not found", cp)
		}
	}
}

type mockRuleAccessor struct{}

func (m *mockRuleAccessor) GetModuleRules(key string) ([]byte, error) {
	return nil, nil
}

func (m *mockRuleAccessor) GetAllRules() (map[string][]byte, error) {
	return nil, nil
}
