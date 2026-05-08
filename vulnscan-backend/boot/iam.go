package boot

import (
	"log/slog"

	iamsdk "code.yt-security.com/public/sdk"
)

func LoadIAM(cfg *Config) *iamsdk.Client {
	slog.Info("[+] ========== IAM SDK 初始化 ==========")

	client, err := iamsdk.NewClient(iamsdk.Config{
		BaseURL:      cfg.IAM.BaseURL,
		ClientID:     cfg.IAM.ClientID,
		ClientSecret: cfg.IAM.ClientSecret,
		PathPrefix:   cfg.IAM.PathPrefix,
	})
	if err != nil {
		panic("IAM SDK 初始化失败: " + err.Error())
	}

	slog.Info("[+] IAM SDK 初始化成功", "base_url", cfg.IAM.BaseURL)
	return client
}
