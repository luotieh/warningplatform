package agent

import "encoding/json"

type TaskEnvelope struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Priority int             `json:"priority"`
	Payload  json.RawMessage `json:"payload"`
}

type TaskResult struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	AgentID    string `json:"agent_id"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Result     string `json:"result,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	// ScreenshotData 截图 JPEG 数据（嵌入式 Agent 在本地执行时填充，不走 JSON 传输）
	ScreenshotData []byte `json:"-"`
	// AnnotatedScreenshotData 带标注（红框）的截图 JPEG 数据
	AnnotatedScreenshotData []byte `json:"-"`
	// ExtraScreenshots 额外截图（如暗链目标页面截图）
	ExtraScreenshots []ExtraScreenshot `json:"-"`
}

// ExtraScreenshot 额外的截图数据。
type ExtraScreenshot struct {
	Label string // 截图标签，如 "暗链目标: http://xxx"
	URL   string // 目标 URL
	Data  []byte // JPEG 数据
}

type HeartbeatReq struct {
	RunningTasks  int     `json:"running_tasks"`
	QueuedTasks   int     `json:"queued_tasks"`
	MaxConcurrent int     `json:"max_concurrent"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	Version       string  `json:"version"`
	IPAddress     string  `json:"ip_address"`
	MacAddress    string  `json:"mac_address"`
}

// ShutdownReq 节点主动下线时上报主控（SIGINT/SIGTERM 优雅退出）。
type ShutdownReq struct {
	Reason       string `json:"reason,omitempty"`
	RunningTasks int    `json:"running_tasks,omitempty"`
	QueuedTasks  int    `json:"queued_tasks,omitempty"`
	Version      string `json:"version,omitempty"`
}
