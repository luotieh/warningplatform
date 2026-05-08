package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulnscan-backend/monitoragent"
)

func main() {
	masterURL := flag.String("master", "", "Master server URL (e.g. http://localhost:8090/api)")
	token := flag.String("token", "", "Agent token (UUID registered in master)")
	concurrency := flag.Int("concurrency", 5, "Max concurrent tasks")
	timeout := flag.Duration("timeout", 5*time.Minute, "Per-task timeout")
	heartbeat := flag.Int("heartbeat", 10, "Heartbeat interval in seconds")
	region := flag.String("region", "", "Agent region label (e.g. cn-north, us-east)")
	label := flag.String("label", "", "Agent description label")
	flag.Parse()

	if *masterURL == "" {
		*masterURL = os.Getenv("MASTER_URL")
	}
	if *token == "" {
		*token = os.Getenv("AGENT_TOKEN")
	}

	if *masterURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "Usage: monitor-agent -master <url> -token <uuid>")
		fmt.Fprintln(os.Stderr, "  or set MASTER_URL and AGENT_TOKEN environment variables")
		os.Exit(1)
	}

	slog.Info("Monitor Agent starting",
		"master", *masterURL,
		"concurrency", *concurrency,
		"version", monitoragent.AgentVersion)

	if *region == "" {
		*region = os.Getenv("AGENT_REGION")
	}
	if *label == "" {
		*label = os.Getenv("AGENT_LABEL")
	}

	agent := monitoragent.NewAgent(monitoragent.AgentConfig{
		MasterURL:     *masterURL,
		AgentToken:    *token,
		MaxConcurrent: *concurrency,
		TaskTimeout:   *timeout,
		HeartbeatSec:  *heartbeat,
		Region:        *region,
		Label:         *label,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent.Start(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	slog.Info("received signal, shutting down", "signal", sig)

	agent.Stop()
	slog.Info("Monitor Agent stopped")
}
