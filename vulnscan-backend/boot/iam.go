package boot

import (
	"log/slog"
	"strings"

	iamsdk "code.yt-security.com/public/access"
)

func LoadIAM(cfg *Config) *iamsdk.Client {
	slog.Info("[+] ========== IAM SDK 初始化 ==========")

	baseURL := cfg.IAM.BaseURL
	if cfg.IAM.PathPrefix != "" {
		baseURL = strings.TrimRight(baseURL, "/") + cfg.IAM.PathPrefix
	}

	client, err := iamsdk.NewRemote(iamsdk.Config{
		BaseURL:      baseURL,
		ClientID:     cfg.IAM.ClientID,
		ClientSecret: cfg.IAM.ClientSecret,
	})
	if err != nil {
		panic("IAM SDK 初始化失败: " + err.Error())
	}

	slog.Info("[+] IAM SDK 初始化成功", "base_url", baseURL)
	return client
}
