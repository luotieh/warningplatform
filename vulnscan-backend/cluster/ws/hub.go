package ws

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/model"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 30 * time.Second
)

// WorkerConn represents a connected worker.
type WorkerConn struct {
	ID     string
	Conn   *websocket.Conn
	Hub    *Hub
	SendCh chan []byte
	mu     sync.Mutex
	closed bool
}

func (wc *WorkerConn) Send(data []byte) {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if wc.closed {
		return
	}
	select {
	case wc.SendCh <- data:
	default:
		slog.Warn("[WSHub] Worker 发送缓冲满，丢弃消息", "worker_id", wc.ID)
	}
}

func (wc *WorkerConn) Close() {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if !wc.closed {
		wc.closed = true
		close(wc.SendCh)
	}
}

// Hub manages all WebSocket connections from workers.
type Hub struct {
	workers    map[string]*WorkerConn
	mu         sync.RWMutex
	clusterSvc clusterContract.ServiceCluster

	registerCh   chan *WorkerConn
	unregisterCh chan *WorkerConn
	stopCh       chan struct{}
}

func NewHub(clusterSvc clusterContract.ServiceCluster) *Hub {
	return &Hub{
		workers:      make(map[string]*WorkerConn),
		clusterSvc:   clusterSvc,
		registerCh:   make(chan *WorkerConn, 32),
		unregisterCh: make(chan *WorkerConn, 32),
		stopCh:       make(chan struct{}),
	}
}

func (h *Hub) Run() {
	slog.Info("[WSHub] WebSocket Hub 已启动")
	for {
		select {
		case conn := <-h.registerCh:
			h.mu.Lock()
			if old, ok := h.workers[conn.ID]; ok {
				old.Close()
			}
			h.workers[conn.ID] = conn
			h.mu.Unlock()
			slog.Info("[WSHub] Worker 连接", "worker_id", conn.ID, "total", len(h.workers))

		case conn := <-h.unregisterCh:
			h.mu.Lock()
			if current, ok := h.workers[conn.ID]; ok && current == conn {
				delete(h.workers, conn.ID)
				conn.Close()
			}
			h.mu.Unlock()
			slog.Info("[WSHub] Worker 断开", "worker_id", conn.ID, "total", len(h.workers))

		case <-h.stopCh:
			h.mu.Lock()
			for _, conn := range h.workers {
				conn.Close()
			}
			h.workers = make(map[string]*WorkerConn)
			h.mu.Unlock()
			slog.Info("[WSHub] Hub 已停止")
			return
		}
	}
}

func (h *Hub) Stop() {
	close(h.stopCh)
}

// SendToWorker sends a message to a specific worker.
func (h *Hub) SendToWorker(workerID string, msgType string, data interface{}) error {
	env, err := NewEnvelope(msgType, data)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}

	h.mu.RLock()
	conn, ok := h.workers[workerID]
	h.mu.RUnlock()

	if !ok {
		return nil
	}

	conn.Send(raw)
	return nil
}

// PushTask directly assigns a task to a connected worker (push model).
func (h *Hub) PushTask(workerID string, task TaskAssignPayload) error {
	return h.SendToWorker(workerID, MsgTypeTaskAssign, task)
}

// SendCommand sends a command to a worker immediately.
func (h *Hub) SendCommand(workerID string, cmd Command) error {
	return h.SendToWorker(workerID, MsgTypeCommand, cmd)
}

// BroadcastCommand sends a command to all connected workers.
func (h *Hub) BroadcastCommand(cmd Command) {
	env, err := NewEnvelope(MsgTypeCommand, cmd)
	if err != nil {
		return
	}
	raw, _ := json.Marshal(env)

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, conn := range h.workers {
		conn.Send(raw)
	}
}

// OnlineWorkerIDs returns IDs of all connected workers.
func (h *Hub) OnlineWorkerIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.workers))
	for id := range h.workers {
		ids = append(ids, id)
	}
	return ids
}

func (h *Hub) WorkerCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.workers)
}

// HandleWorkerConn is called per-connection; it manages read/write goroutines.
func (h *Hub) HandleWorkerConn(conn *websocket.Conn) {
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	wc := &WorkerConn{
		Conn:   conn,
		Hub:    h,
		SendCh: make(chan []byte, 64),
	}

	go h.writePump(wc)
	h.readPump(wc)
}

func (h *Hub) writePump(wc *WorkerConn) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		wc.Conn.Close()
	}()

	for {
		select {
		case msg, ok := <-wc.SendCh:
			wc.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				wc.Conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := wc.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			wc.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := wc.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) readPump(wc *WorkerConn) {
	defer func() {
		h.unregisterCh <- wc
		wc.Conn.Close()
	}()

	for {
		_, message, err := wc.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Warn("[WSHub] Worker 异常断开", "worker_id", wc.ID, "error", err)
			}
			return
		}

		var env Envelope
		if err := json.Unmarshal(message, &env); err != nil {
			slog.Warn("[WSHub] 消息解析失败", "error", err)
			continue
		}

		h.handleMessage(wc, &env)
	}
}

func (h *Hub) handleMessage(wc *WorkerConn, env *Envelope) {
	switch env.Type {
	case MsgTypeRegister:
		var payload RegisterPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}
		wc.ID = payload.WorkerID
		h.registerCh <- wc

		ack := RegisterAckPayload{OK: true}
		h.sendReply(wc, MsgTypeRegisterAck, ack)

	case MsgTypeHeartbeat:
		var payload HeartbeatPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}

		hbPayload := &clusterContract.HeartbeatPayload{
			WorkerID:          payload.WorkerID,
			ActiveTasks:       payload.ActiveTasks,
			Capacity:          payload.Capacity,
			CPUUsage:          payload.CPUUsage,
			MemUsage:          payload.MemUsage,
			BandwidthMbps:     payload.BandwidthMbps,
			AvgLatencyMs:      payload.AvgLatencyMs,
			ProxyHealthyCount: payload.ProxyHealthyCount,
			ProxyTotalCount:   payload.ProxyTotalCount,
		}

		resp, err := h.clusterSvc.Heartbeat(nil, hbPayload)
		ack := HeartbeatAckPayload{OK: err == nil}
		if err == nil && resp != nil {
			for _, cmd := range resp.Commands {
				ack.Commands = append(ack.Commands, Command{
					Action: cmd.Action,
					TaskID: cmd.TaskID,
					Reason: cmd.Reason,
				})
			}
		}
		h.sendReply(wc, MsgTypeHeartbeatAck, ack)

	case MsgTypePollTask:
		var payload PollTaskPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}

		tasks, err := h.clusterSvc.PollTask(nil, payload.WorkerID, payload.Slots)
		if err != nil || len(tasks) == 0 {
			return
		}

		for _, task := range tasks {
			assign := TaskAssignPayload{
				TaskID:     task.ID,
				Name:       task.Name,
				Targets:    task.Targets,
				Config:     task.Config,
				Parameters: task.Parameters,
				Priority:   task.Priority,
				Type:       task.Type,
			}
			h.sendReply(wc, MsgTypeTaskAssign, assign)
		}

	case MsgTypeTaskProgress:
		var payload TaskProgressPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}
		h.clusterSvc.ReportTaskResult(nil, &clusterContract.TaskResult{
			TaskID:       payload.TaskID,
			WorkerID:     payload.WorkerID,
			Status:       "running",
			Progress:     payload.Progress,
			CurrentStage: payload.CurrentStage,
		})

	case MsgTypeTaskResult:
		var payload TaskResultPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}
		var vulns []model.Vulnerability
		for _, vb := range payload.Vulns {
			vulns = append(vulns, model.Vulnerability{
				Target:       vb.Target,
				Port:         vb.Port,
				Title:        vb.Title,
				Severity:     vb.Severity,
				ModuleID:     vb.ModuleID,
				Evidence:     vb.Evidence,
				DetectMethod: "active",
				Status:       model.VulnStatusOpen,
			})
		}
		h.clusterSvc.ReportTaskResult(nil, &clusterContract.TaskResult{
			TaskID:          payload.TaskID,
			WorkerID:        payload.WorkerID,
			Status:          payload.Status,
			Progress:        payload.Progress,
			Error:           payload.Error,
			FinishedAt:      payload.FinishedAt,
			Vulnerabilities: vulns,
		})
		h.sendReply(wc, MsgTypeTaskResultAck, map[string]bool{"ok": true})

	case MsgTypeBanReport:
		var payload BanReportPayload
		if err := json.Unmarshal(env.Data, &payload); err != nil {
			return
		}
		h.clusterSvc.ReportBan(nil, &clusterContract.BanReport{
			WorkerID:   payload.WorkerID,
			TaskID:     payload.TaskID,
			TargetHost: payload.TargetHost,
			Reason:     payload.Reason,
		})

	case MsgTypePong:
		// no-op

	default:
		slog.Debug("[WSHub] 未知消息类型", "type", env.Type)
	}
}

func (h *Hub) sendReply(wc *WorkerConn, msgType string, data interface{}) {
	env, err := NewEnvelope(msgType, data)
	if err != nil {
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	wc.Send(raw)
}
