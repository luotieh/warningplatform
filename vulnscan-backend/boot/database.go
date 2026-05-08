package boot

import (
	"log/slog"

	"code.yt-security.com/public/core/v2/db"
)

func LoadDB(config *Config) *db.DB {
	db1, err := db.NewDB(config.DB)
	if err != nil {
		slog.Error("[!] 数据库初始化失败", "error", err)
		panic("数据库初始化失败: " + err.Error())
	}
	slog.Info("[+] 数据库初始化成功")
	return db1
}
