package boot

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/access/auth"
)

func LoadIAM(cfg *Config) *iamsdk.Client {
	slog.Info("[+] ========== IAM SDK 初始化 ==========")
	if strings.EqualFold(strings.TrimSpace(cfg.IAM.Mode), "local") {
		client, err := iamsdk.NewLocal(iamsdk.LocalConfig{
			Authenticator: func(context.Context, string, string) (*auth.UserClaims, error) {
				return nil, errors.New("IAM SDK local authenticator is not used")
			},
		})
		if err != nil {
			panic("IAM SDK 本地模式初始化失败: " + err.Error())
		}
		slog.Info("[+] IAM SDK 本地模式初始化成功")
		return client
	}

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
