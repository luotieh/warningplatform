package boot

import (
	"log/slog"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/os/qcfg"
	"code.yt-security.com/public/core/v2/web"
)

type IAMConfig struct {
	BaseURL      string `json:"base_url" toml:"base_url"`
	ClientID     string `json:"client_id" toml:"client_id"`
	ClientSecret string `json:"client_secret" toml:"client_secret"`
	PathPrefix   string `json:"path_prefix" toml:"path_prefix"`
}

type CacheConfig struct {
	Host     string `json:"host" toml:"host"`
	Port     int    `json:"port" toml:"port"`
	Username string `json:"username" toml:"username"`
	Password string `json:"password" toml:"password"`
	DB       int    `json:"db" toml:"db"`
	Prefix   string `json:"prefix" toml:"prefix"`
}

type SSOConfig struct {
	CallbackURI           string `json:"callback_uri" toml:"callback_uri"`
	SuccessRedirect       string `json:"success_redirect" toml:"success_redirect"`
	CookieSecret          string `json:"cookie_secret" toml:"cookie_secret"`
	TokenRelayCallbackURI string `json:"token_relay_callback_uri" toml:"token_relay_callback_uri"`
}

// FederationUpstreamConfig 被 federation/client 包引用，保留结构体定义
type FederationUpstreamConfig struct {
	CentralURL       string `json:"central_url"`
	APIToken         string `json:"api_token"`
	TLSCert          string `json:"tls_cert"`
	TLSKey           string `json:"tls_key"`
	CACert           string `json:"ca_cert"`
	LicenseFile      string `json:"license_file"`
	SyncInterval     string `json:"sync_interval"`
	ReportInterval   string `json:"report_interval"`
	OfflineGraceDays int    `json:"offline_grace_days"`
}

type NatsConfig struct {
	URL            string `json:"url" toml:"url"`
	Token          string `json:"token" toml:"token"`
	User           string `json:"user" toml:"user"`
	Password       string `json:"password" toml:"password"`
	CredsFile      string `json:"creds_file" toml:"creds_file"`
	NKeySeed       string `json:"nkey_seed" toml:"nkey_seed"`
	TLSCA          string `json:"tls_ca" toml:"tls_ca"`
	TLSCert        string `json:"tls_cert" toml:"tls_cert"`
	TLSKey         string `json:"tls_key" toml:"tls_key"`
	ConnectTimeout int    `json:"connect_timeout" toml:"connect_timeout"`
	TaskStream     string `json:"task_stream" toml:"task_stream"`
	ResultStream   string `json:"result_stream" toml:"result_stream"`
	KVBucket       string `json:"kv_bucket" toml:"kv_bucket"`
	ObjBucket      string `json:"obj_bucket" toml:"obj_bucket"`
}

type Config struct {
	Web   web.Config  `json:"web" toml:"web"`
	DB    db.Config   `json:"db" toml:"db"`
	Cache CacheConfig `json:"cache" toml:"cache"`
	IAM   IAMConfig   `json:"iam" toml:"iam"`
	SSO   SSOConfig   `json:"sso" toml:"sso"`
	Nats  NatsConfig  `json:"nats" toml:"nats"`
}

func LoadConfig() *Config {
	slog.Info("[+] ========== 配置初始化 ==========")
	c1 := qcfg.New()
	c1 = c1.SetConfigPath("config.toml")
	err := c1.Load()
	if err != nil {
		slog.Error("[!] 配置文件加载失败", "error", err)
		panic("配置文件加载失败: " + err.Error())
	}
	slog.Info("[+] 配置文件加载成功")

	var mConfig Config
	err = c1.Unmarshal(&mConfig)
	if err != nil {
		slog.Error("[!] 配置文件解析失败", "error", err)
		panic("配置文件解析失败: " + err.Error())
	}

	if mConfig.Cache.Prefix == "" {
		mConfig.Cache.Prefix = "vs:"
	}

	slog.Info("[+] ========== 配置初始化结束 ==========")
	return &mConfig
}
