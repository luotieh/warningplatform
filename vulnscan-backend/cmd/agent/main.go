package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/agent/monitor"
	"vulnscan-backend/agent/scanner"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("starting unified agent", "version", agent.Version)

	masterURL := os.Getenv("MASTER_URL")
	if masterURL == "" {
		masterURL = "http://localhost:8080"
	}

	token := os.Getenv("AGENT_TOKEN")
	if token == "" {
		hostname, _ := os.Hostname()
		token = fmt.Sprintf("agent-%s-%d", hostname, os.Getpid())
	}

	maxConcurrent := 10
	if v := os.Getenv("MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxConcurrent = n
		}
	}

	cfg := agent.Config{
		MasterURL:         masterURL,
		Token:             token,
		MaxConcurrent:     maxConcurrent,
		TaskTimeout:       10 * time.Minute,
		HeartbeatInterval: 10 * time.Second,
	}

	monitorExec := monitor.NewExecutor(masterURL, token)
	scannerExec := scanner.NewExecutor()

	a := agent.New(cfg, monitorExec, scannerExec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		slog.Error("agent start failed", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down...")
	a.Stop()
	slog.Info("agent exited")
}
