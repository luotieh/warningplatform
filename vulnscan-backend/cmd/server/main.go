package main

import (
	"context"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
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

	go func() {
		pprofAddr := os.Getenv("PPROF_ADDR")
		if pprofAddr == "" {
			pprofAddr = "127.0.0.1:6060"
		}
		slog.Info("[+] pprof 已启动", "addr", "http://"+pprofAddr+"/debug/pprof/")
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			slog.Warn("[!] pprof 启动失败", "error", err)
		}
	}()

	handlers := di.InitializeHandlers()
	handlers.RouteLoad()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- handlers.Web.ListenAndServeWithSignal()
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

func setupLogger() {
	level := slog.LevelInfo
	if raw := os.Getenv("LOG_LEVEL"); raw != "" {
		if l, err := agent.ParseLogLevel(raw); err == nil {
			level = l
		}
	}
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
		return
	}
	agent.SetupCLILogger(level, os.Stdout)
}
