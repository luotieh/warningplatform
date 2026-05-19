package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRuntimeConfig_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("master_url: http://from-file:8080\nsecret: file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MASTER_URL", "http://from-env:9090")
	t.Setenv("AGENT_SECRET", "env-secret")

	cfg, err := LoadRuntimeConfig(RuntimeConfigOverrides{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterURL != "http://from-env:9090" {
		t.Fatalf("master_url = %q, want env override", cfg.MasterURL)
	}
	if cfg.Secret != "env-secret" {
		t.Fatalf("secret = %q, want env override", cfg.Secret)
	}
}

func TestLoadRuntimeConfig_CredentialsOverlay(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "creds.json")
	cred := `{"version":1,"master_url":"http://master:8080","node_uuid":"node-1","secret":"s3cret","topology":"master_public_node_private"}`
	if err := os.WriteFile(credPath, []byte(cred), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeConfig(RuntimeConfigOverrides{
		CredentialsFile: credPath,
		Token:           "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "node-1" || cfg.Secret != "s3cret" {
		t.Fatalf("credentials overlay failed: token=%q secret=%q", cfg.Token, cfg.Secret)
	}
	if cfg.Topology != "master_public_node_private" {
		t.Fatalf("topology = %q", cfg.Topology)
	}
}

func TestRuntimeConfig_AgentConfig_Durations(t *testing.T) {
	cfg := RuntimeConfig{
		MasterURL:         "http://localhost:8080",
		Token:             "t",
		TaskTimeout:       "5m",
		HeartbeatInterval: "15s",
	}
	agentCfg, err := cfg.AgentConfig()
	if err != nil {
		t.Fatal(err)
	}
	if agentCfg.TaskTimeout != 5*time.Minute {
		t.Fatalf("task timeout = %v", agentCfg.TaskTimeout)
	}
	if agentCfg.HeartbeatInterval != 15*time.Second {
		t.Fatalf("heartbeat = %v", agentCfg.HeartbeatInterval)
	}
}
