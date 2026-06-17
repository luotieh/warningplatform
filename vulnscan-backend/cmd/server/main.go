package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/di"
)

func main() {
	setupLogger()

	handlers := di.InitializeHandlers()
	handlers.SetLogLevel(LogLevel)
	handlers.RouteLoad()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- handlers.Web.ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		slog.Info("[*] 收到关闭信号，开始优雅退出...")
	case err := <-srvErr:
		if err != nil {
			slog.Error("[!] 服务异常退出", "error", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handlers.Shutdown()
		slog.Info("[+] 所有组件已安全关闭")
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("[+] 程序已安全退出")
	case <-shutdownCtx.Done():
		slog.Warn("[!] 优雅退出超时，强制退出")
	}
}

// LogLevel 运行时可调整的日志级别，可通过 /api/system/log-level 接口修改。
var LogLevel = new(slog.LevelVar)

func setupLogger() {
	level := slog.LevelInfo
	if raw := os.Getenv("LOG_LEVEL"); raw != "" {
		if l, err := agent.ParseLogLevel(raw); err == nil {
			level = l
		}
	}
	LogLevel.Set(level)

	if strings.EqualFold(os.Getenv("LOG_QUIET"), "true") || strings.EqualFold(os.Getenv("LOG_QUIET"), "1") {
		LogLevel.Set(slog.LevelError)
	}

	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: LogLevel})))
		return
	}
	slog.SetDefault(slog.New(agent.NewCLIHandler(os.Stdout, &slog.HandlerOptions{Level: LogLevel})))
	slog.Info("log level", "level", LogLevel.Level().String())
}
