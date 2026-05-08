package main

import (
	"log/slog"
	"os"

	"vulnscan-backend/di"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("[+] 启动模式: Master (Web API + 调度器)")

	handlers := di.InitializeHandlers()
	handlers.RouteLoad()

	if err := handlers.Web.ListenAndServeWithSignal(); err != nil {
		slog.Error("[!] 服务退出", "error", err)
		os.Exit(1)
	}

	handlers.Shutdown()
	slog.Info("[+] Master 已安全退出")
}
