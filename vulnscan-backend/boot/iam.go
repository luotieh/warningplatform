package boot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"code.yt-security.com/public/access/auth"
	identity "code.yt-security.com/public/access/identity"
	identityLocal "code.yt-security.com/public/access/identity/local"
	iamsdk "code.yt-security.com/public/access"
)

func LoadIAM(cfg *Config) *iamsdk.Client {
	slog.Info("[+] ========== IAM SDK 初始化 ==========")
	if strings.EqualFold(strings.TrimSpace(cfg.IAM.Mode), "local") {
		password := cfg.IAM.LocalAdminPassword
		if password == "" { password = "admin" }
		identityStore := identityLocal.NewMemoryStore()
		identityStore.AddUser(identity.User{
			ID:       "admin",
			UserName: "admin",
			NickName: "本地管理员",
			Status:   identity.StatusNormal,
			Roles:    []string{"admin"},
		})
		client, err := iamsdk.NewLocal(iamsdk.LocalConfig{
			Config: iamsdk.Config{Mode: iamsdk.ModeLocal},
			JWTSecret: "manage-platform-local-dev-secret",
			PrivilegedRoles: []string{"admin"},
			IdentityStore: identityStore,
			Authenticator: func(_ context.Context, account, supplied string) (*auth.UserClaims, error) {
				if account != "admin" || supplied != password { return nil, fmt.Errorf("invalid local credentials") }
				return &auth.UserClaims{UserID: "admin", Account: "admin", Roles: []string{"admin"}, IsPrivileged: true}, nil
			},
		})
		if err != nil { panic("本地 IAM 初始化失败: " + err.Error()) }
		slog.Info("[+] 本地 IAM 初始化成功")
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
