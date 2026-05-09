package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vulnscan-backend/boot"
	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
	"vulnscan-backend/scan/module/certcheck"
	"vulnscan-backend/scan/module/dirscan"
	"vulnscan-backend/scan/module/dnsall"
	"vulnscan-backend/scan/module/favicon"
	"vulnscan-backend/scan/module/icmp"
	"vulnscan-backend/scan/module/infoleak"
	"vulnscan-backend/scan/module/portscan"
	"vulnscan-backend/scan/module/serviceprobe"
	"vulnscan-backend/scan/module/sqli"
	"vulnscan-backend/scan/module/ssrf"
	"vulnscan-backend/scan/module/weakpass"
	"vulnscan-backend/scan/module/webcrawl"
	"vulnscan-backend/scan/module/xss"
)

type WorkerAgent struct {
	id          string
	masterURL   string
	token       string
	capacity    int
	activeTasks atomic.Int32
	ctx         context.Context
	cancel      context.CancelFunc
	httpClient  *http.Client
	taskCancel  sync.Map
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("[+] 启动模式: Worker (扫描执行节点)")

	cfg := boot.LoadConfig()

	workerID := os.Getenv("WORKER_ID")
	if workerID == "" {
		hostname, _ := os.Hostname()
		workerID = fmt.Sprintf("worker-%s-%d", hostname, os.Getpid())
	}

	masterURL := os.Getenv("MASTER_URL")
	if masterURL == "" {
		masterURL = fmt.Sprintf("http://localhost:%d", cfg.Web.Port)
	}

	capacity := 50
	if envCap := os.Getenv("WORKER_CAPACITY"); envCap != "" {
		if v, err := strconv.Atoi(envCap); err == nil && v > 0 {
			capacity = v
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	agent := &WorkerAgent{
		id:        workerID,
		masterURL: masterURL,
		capacity:  capacity,
		ctx:       ctx,
		cancel:    cancel,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}

	slog.Info("[+] Worker 配置",
		"worker_id", workerID,
		"master_url", masterURL,
		"capacity", capacity,
	)

	if err := agent.register(); err != nil {
		slog.Error("[!] 注册到 Master 失败", "error", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		agent.heartbeatLoop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		agent.pollLoop()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	slog.Info("[+] Worker 已启动，开始拉取任务...")
	<-sigCh

	slog.Info("[*] 收到退出信号，停止任务并注销...")
	cancel()
	wg.Wait()

	agent.unregister()
	slog.Info("[+] Worker 已安全退出")
}

func (w *WorkerAgent) register() error {
	hostname, _ := os.Hostname()
	localIP := getLocalIP()

	payload := map[string]interface{}{
		"id":       w.id,
		"hostname": hostname,
		"ip":       localIP,
		"capacity": w.capacity,
		"version":  boot.GetVersion(),
	}

	resp, err := w.doPost("/cluster/workers/register", payload)
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	slog.Info("[+] Worker 注册成功", "worker_id", w.id, "ip", localIP)
	return nil
}

func (w *WorkerAgent) unregister() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST",
		w.masterURL+"/cluster/workers/"+w.id+"/unregister", nil)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		slog.Warn("[!] 注销失败", "error", err)
		return
	}
	resp.Body.Close()
	slog.Info("[+] Worker 已注销", "worker_id", w.id)
}

func (w *WorkerAgent) heartbeatLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.sendHeartbeat()
		}
	}
}

func (w *WorkerAgent) sendHeartbeat() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	cpuUsage := float64(runtime.NumGoroutine()) / float64(runtime.GOMAXPROCS(0)*100) * 100
	memUsage := float64(memStats.Alloc) / float64(memStats.Sys) * 100

	payload := clusterContract.HeartbeatPayload{
		WorkerID:    w.id,
		ActiveTasks: int(w.activeTasks.Load()),
		Capacity:    w.capacity,
		CPUUsage:    cpuUsage,
		MemUsage:    memUsage,
		Version:     boot.GetVersion(),
	}

	resp, err := w.doPost("/cluster/workers/heartbeat", payload)
	if err != nil {
		slog.Warn("[!] 心跳失败", "error", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Code int                               `json:"code"`
		Data clusterContract.HeartbeatResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	for _, cmd := range result.Data.Commands {
		w.handleCommand(cmd)
	}
}

func (w *WorkerAgent) handleCommand(cmd clusterContract.WorkerCommand) {
	slog.Info("[+] 收到 Master 指令", "action", cmd.Action, "task_id", cmd.TaskID, "reason", cmd.Reason)

	switch cmd.Action {
	case clusterContract.CmdCancelTask:
		if cancelFn, ok := w.taskCancel.Load(cmd.TaskID); ok {
			cancelFn.(context.CancelFunc)()
		}
	case clusterContract.CmdDrainWorker:
		slog.Warn("[!] Worker 进入 drain 模式，不再接受新任务")
		w.capacity = 0
	case clusterContract.CmdResumeWorker:
		slog.Info("[+] Worker 恢复正常模式")
		w.capacity = 5
	}
}

func (w *WorkerAgent) pollLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.tryPollAndExecute()
		}
	}
}

func (w *WorkerAgent) tryPollAndExecute() {
	active := int(w.activeTasks.Load())
	if active >= w.capacity {
		return
	}

	slots := w.capacity - active
	if slots > 3 {
		slots = 3
	}

	payload := clusterContract.PollTaskRequest{
		WorkerID: w.id,
		Slots:    slots,
	}

	resp, err := w.doPost("/cluster/tasks/poll", payload)
	if err != nil {
		slog.Debug("[!] Poll 失败", "error", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Code int               `json:"code"`
		Data []*model.ScanTask `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	if result.Data == nil || len(result.Data) == 0 {
		return
	}

	for _, task := range result.Data {
		if task == nil {
			continue
		}
		w.activeTasks.Add(1)
		go w.executeTask(task)
	}
}

func (w *WorkerAgent) executeTask(task *model.ScanTask) {
	defer w.activeTasks.Add(-1)

	taskCtx, taskCancel := context.WithCancel(w.ctx)
	defer taskCancel()
	w.taskCancel.Store(task.ID, taskCancel)
	defer w.taskCancel.Delete(task.ID)

	slog.Info("[+] 开始执行任务",
		"task_id", task.ID,
		"targets", len(task.Targets),
	)

	var targets []*engine.Target
	for _, addr := range task.Targets {
		targets = append(targets, &engine.Target{Host: addr})
	}

	modules := w.resolveModules(task)
	config := make(map[string]interface{})
	if task.Parameters != nil {
		for k, v := range task.Parameters {
			config[k] = v
		}
	}

	var allFindings []*engine.Finding
	totalStages := len(modules)

	for i, mod := range modules {
		select {
		case <-taskCtx.Done():
			w.reportResult(task.ID, model.TaskStatusCancelled, float64(i)/float64(totalStages)*100, "", nil)
			return
		default:
		}

		modCtx, modCancel := context.WithTimeout(taskCtx, 10*time.Minute)
		result, err := mod.Run(modCtx, targets, config)
		modCancel()

		if err != nil {
			slog.Warn("[!] 模块执行失败", "task", task.ID, "module", mod.ID(), "error", err)
			continue
		}

		allFindings = append(allFindings, result.Findings...)

		if result.Targets != nil {
			seen := make(map[string]struct{})
			for _, t := range targets {
				seen[t.Host+"|"+t.IP+"|"+t.URL] = struct{}{}
			}
			for _, t := range result.Targets {
				key := t.Host + "|" + t.IP + "|" + t.URL
				if _, ok := seen[key]; !ok {
					targets = append(targets, t)
					seen[key] = struct{}{}
				}
			}
		}

		progress := float64(i+1) / float64(totalStages) * 100
		w.reportProgress(task.ID, progress, mod.Category())
	}

	var vulns []model.Vulnerability
	for _, f := range allFindings {
		target := ""
		port := 0
		protocol := ""
		if f.Target != nil {
			target = f.Target.Host
			if f.Target.IP != "" {
				target = f.Target.IP
			}
			if f.Target.URL != "" {
				target = f.Target.URL
			}
			port = f.Target.Port
			protocol = f.Target.Protocol
		}
		severity := f.Severity
		if severity == "" {
			severity = "info"
		}
		vulns = append(vulns, model.Vulnerability{
			TaskID:       task.ID,
			Target:       target,
			Port:         port,
			Protocol:     protocol,
			Title:        f.Title,
			Description:  f.Description,
			Severity:     severity,
			Category:     f.Type,
			ModuleID:     f.ModuleID,
			DetectMethod: "active",
			Confidence:   f.Confidence,
			Evidence:     f.Evidence,
			Status:       model.VulnStatusOpen,
		})
	}

	w.reportResult(task.ID, model.TaskStatusCompleted, 100, "", vulns)

	slog.Info("[+] 任务执行完成",
		"task_id", task.ID,
		"findings", len(allFindings),
	)
}

func (w *WorkerAgent) resolveModules(task *model.ScanTask) []engine.ScanModule {
	profile := "full"
	if task.Config != nil {
		if p, ok := task.Config["profile"].(string); ok {
			profile = p
		}
	}
	if task.Type != "" {
		profile = task.Type
	}

	pl := payload.NewLoader(nil)
	_ = pl.LoadAll()

	switch profile {
	case "quick":
		return []engine.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
		}
	case "vuln":
		return []engine.ScanModule{
			sqli.New(pl),
			xss.New(pl),
			weakpass.New(),
			ssrf.New("", pl),
		}
	case "recon":
		return []engine.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
			dnsall.New(),
			favicon.New(),
			certcheck.New(),
			infoleak.New(),
		}
	default:
		return []engine.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
			dnsall.New(),
			favicon.New(),
			certcheck.New(),
			infoleak.New(),
			dirscan.New(),
			sqli.New(pl),
			xss.New(pl),
			weakpass.New(),
			ssrf.New("", pl),
		}
	}
}

func (w *WorkerAgent) reportProgress(taskID string, progress float64, stage string) {
	payload := clusterContract.TaskResult{
		TaskID:       taskID,
		WorkerID:     w.id,
		Status:       model.TaskStatusRunning,
		Progress:     progress,
		CurrentStage: stage,
	}

	resp, err := w.doPost("/cluster/tasks/report", payload)
	if err != nil {
		slog.Debug("[!] 进度上报失败", "error", err)
		return
	}
	resp.Body.Close()
}

func (w *WorkerAgent) reportResult(taskID, status string, progress float64, errMsg string, vulns []model.Vulnerability) {
	now := time.Now()
	payload := clusterContract.TaskResult{
		TaskID:          taskID,
		WorkerID:        w.id,
		Status:          status,
		Progress:        progress,
		Vulnerabilities: vulns,
		Error:           errMsg,
		FinishedAt:      &now,
	}

	resp, err := w.doPost("/cluster/tasks/report", payload)
	if err != nil {
		slog.Error("[!] 结果上报失败", "task_id", taskID, "error", err)
		return
	}
	resp.Body.Close()
}

func (w *WorkerAgent) doPost(path string, payload interface{}) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", w.masterURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	return w.httpClient.Do(req)
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
