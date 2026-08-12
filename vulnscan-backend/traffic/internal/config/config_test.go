package config

import (
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/pelletier/go-toml/v2"
)

func TestBuildAndParseStoreDSN(t *testing.T) {
	dsn := BuildStoreDSN(StoreSettings{
		Host:     "10.20.30.144",
		Port:     3306,
		User:     "db",
		Password: "secret",
		DBName:   "traffic",
	})
	if dsn == "" {
		t.Fatal("empty dsn")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	if cfg.Addr != "10.20.30.144:3306" || cfg.User != "db" || cfg.Passwd != "secret" || cfg.DBName != "traffic" {
		t.Fatalf("dsn mismatch: %+v", cfg)
	}
	if !cfg.ParseTime {
		t.Fatal("parseTime should be forced on")
	}
	host, port, user, dbname, passwd := parseStoreDSN(dsn)
	if host != "10.20.30.144" || port != 3306 || user != "db" || dbname != "traffic" || passwd != "secret" {
		t.Fatalf("parseStoreDSN = %s/%d/%s/%s/%s", host, port, user, dbname, passwd)
	}
}

// TestUpsertStoreSettingsInMemory 验证 [traffic] 段 upsert 后的 TOML 仍可解析、
// 且 store 键被正确写入（不落盘真实 config.toml）。
func TestUpsertStoreSettingsInMemory(t *testing.T) {
	raw, err := os.ReadFile("../../../config.toml")
	if err != nil {
		t.Skipf("repo config.toml not found: %v", err)
	}
	dsn := BuildStoreDSN(StoreSettings{Host: "h", Port: 3307, User: "u", Password: "p", DBName: "d"})
	next := upsertTOMLSectionValues(string(raw), "traffic", map[string]string{
		"store_backend":   `"mysql"`,
		"database_url":    quoteTOMLString(dsn),
		"auto_migrate":    "true",
		"db_wait_seconds": "45",
	}, []string{"store_backend", "database_url", "auto_migrate", "db_wait_seconds"})

	var parsed struct {
		Traffic struct {
			StoreBackend  string `toml:"store_backend"`
			DatabaseURL   string `toml:"database_url"`
			AutoMigrate   bool   `toml:"auto_migrate"`
			DBWaitSeconds int    `toml:"db_wait_seconds"`
		} `toml:"traffic"`
	}
	if err := toml.Unmarshal([]byte(next), &parsed); err != nil {
		t.Fatalf("upserted toml invalid: %v", err)
	}
	if parsed.Traffic.StoreBackend != "mysql" || !strings.Contains(parsed.Traffic.DatabaseURL, "@tcp(h:3307)") ||
		!parsed.Traffic.AutoMigrate || parsed.Traffic.DBWaitSeconds != 45 {
		t.Fatalf("upsert mismatch: %+v", parsed.Traffic)
	}
}
