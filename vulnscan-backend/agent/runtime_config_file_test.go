package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRuntimeConfigTemplate_TOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	if err := WriteRuntimeConfigTemplate(path, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterURL == "" {
		t.Fatal("master_url should be set in template")
	}
	if cfg.TaskTimeout != "10m" {
		t.Fatalf("task_timeout = %q", cfg.TaskTimeout)
	}
}

func TestWriteRuntimeConfigTemplate_ExistsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	if err := WriteRuntimeConfigTemplate(path, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteRuntimeConfigTemplate(path, false); err == nil {
		t.Fatal("expected error when file exists")
	}
}

func TestLoadRuntimeConfigFile_TOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.toml")
	content := `master_url = "http://test:8080/api"
log_level = "debug"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterURL != "http://test:8080/api" || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
}
