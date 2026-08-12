package traffic

import (
	"testing"

	trafficconfig "vulnscan-backend/traffic/internal/config"
)

func TestStoreSettingsFromBodyPasswordFallback(t *testing.T) {
	current := trafficconfig.StoreSettings{
		StoreBackend: "mysql",
		Host:         "172.17.0.1",
		Port:         3306,
		User:         "yuntian",
		Password:     "saved-secret",
		DBName:       "traffic",
	}

	// 未传 password：回填当前配置密码（“留空不修改”语义）
	got := storeSettingsFromBody(map[string]any{
		"host":     "172.17.0.1",
		"port":     float64(3306),
		"user":     "yuntian",
		"db_name":  "traffic",
	}, current)
	if got.Password != "saved-secret" {
		t.Fatalf("password fallback failed: %q", got.Password)
	}
	if got.Host != "172.17.0.1" || got.DBName != "traffic" || got.Port != 3306 {
		t.Fatalf("fields not parsed: %+v", got)
	}

	// 显式传空字符串：保持空（允许测试无密码连接场景）
	got = storeSettingsFromBody(map[string]any{"password": ""}, current)
	if got.Password != "" {
		t.Fatalf("explicit empty password should stay empty, got %q", got.Password)
	}

	// 显式传新密码：使用新密码
	got = storeSettingsFromBody(map[string]any{"password": "new-secret"}, current)
	if got.Password != "new-secret" {
		t.Fatalf("explicit password not used: %q", got.Password)
	}
}
