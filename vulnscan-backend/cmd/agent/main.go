package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"vulnscan-backend/agent"
	"vulnscan-backend/agent/monitor"
	"vulnscan-backend/agent/scanner"
	"vulnscan-backend/pkg/nodeenroll"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll":
			os.Exit(runEnroll(os.Args[2:]))
		case "decrypt-credentials":
			os.Exit(runDecryptCredentials(os.Args[2:]))
		case "help", "-h", "--help":
			printAgentHelp()
			return
		}
	}
	runAgentMain()
}

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	out := fs.String("out", "node-enrollment.json", "enrollment JSON path (RSA private key is written alongside as .key, keep it on the node only)")
	_ = fs.Parse(args)
	if err := nodeenroll.WriteEnrollmentBundle(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	key := nodeenroll.EnrollmentKeyPath(*out)
	fmt.Fprintf(os.Stderr, "wrote %s\nwrote %s (do not upload; required for decrypt-credentials)\n", *out, key)
	return 0
}

func runDecryptCredentials(args []string) int {
	fs := flag.NewFlagSet("decrypt-credentials", flag.ExitOnError)
	envPath := fs.String("envelope", "", "envelope JSON file from master (encrypted)")
	keyPath := fs.String("key", "", "RSA private key PEM file from enroll (.key)")
	outPath := fs.String("out", "node-agent.credentials.json", "output cleartext credentials for AGENT_CREDENTIALS_FILE")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s decrypt-credentials -envelope <path> -key <path> [-out <path>]\n", os.Args[0])
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *envPath == "" || *keyPath == "" {
		fs.Usage()
		return 1
	}
	if err := agent.DecryptCredentialEnvelopeToFile(*envPath, *keyPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s — set AGENT_CREDENTIALS_FILE to this path and start the agent.\n", *outPath)
	return 0
}

func printAgentHelp() {
	fmt.Printf(`Unified scan/monitor agent.

Run without subcommands to start the agent (requires MASTER_URL / AGENT_TOKEN or AGENT_CREDENTIALS_FILE).

Subcommands:
  enroll [-out node-enrollment.json]
        Generate machine enrollment JSON + RSA key pair for onboarding.
        Upload only the .json to the master; keep the .key file on this machine.

  decrypt-credentials -envelope <file> -key <file> [-out credentials.json]
        Decrypt credential envelope from the master using the private .key from enroll.

`)
}

func runAgentMain() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("starting unified agent", "version", agent.Version)

	masterURL := os.Getenv("MASTER_URL")
	if masterURL == "" {
		masterURL = "http://localhost:8080"
	}

	token := os.Getenv("AGENT_TOKEN")
	secret := strings.TrimSpace(os.Getenv("AGENT_SECRET"))
	topology := strings.TrimSpace(os.Getenv("AGENT_TOPOLOGY"))

	if credPath := strings.TrimSpace(os.Getenv("AGENT_CREDENTIALS_FILE")); credPath != "" {
		cred, err := agent.LoadCredentialsFile(credPath)
		if err != nil {
			slog.Error("load AGENT_CREDENTIALS_FILE failed", "path", credPath, "error", err)
			os.Exit(1)
		}
		if cred.MasterURL != "" {
			masterURL = cred.MasterURL
		}
		token = cred.NodeUUID
		secret = cred.Secret
		if cred.Topology != "" {
			topology = cred.Topology
		}
	}

	if token == "" {
		hostname, _ := os.Hostname()
		token = fmt.Sprintf("agent-%s-%d", hostname, os.Getpid())
	}

	// 0 = 按本机 CPU/内存自动计算并发（预留 10% 系统余量）；MAX_CONCURRENT>0 为手动上限
	maxConcurrent := 0
	if v := os.Getenv("MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxConcurrent = n
		}
	}

	cfg := agent.Config{
		MasterURL:         masterURL,
		Token:             token,
		Secret:            secret,
		Topology:          topology,
		MaxConcurrent:     maxConcurrent,
		TaskTimeout:       10 * time.Minute,
		HeartbeatInterval: 10 * time.Second,
	}

	monitorExec := monitor.NewExecutor(masterURL, token, cfg.Secret)
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
