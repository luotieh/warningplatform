package monitoragent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type MasterClient struct {
	baseURL    string
	agentToken string
	httpClient *http.Client
}

func NewMasterClient(baseURL, agentToken string) *MasterClient {
	return &MasterClient{
		baseURL:    baseURL,
		agentToken: agentToken,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *MasterClient) doJSON(ctx context.Context, method, path string, body any) ([]byte, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", c.agentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *MasterClient) Heartbeat(ctx context.Context, status *HeartbeatReq) error {
	_, err := c.doJSON(ctx, "POST", "/agent-api/heartbeat", status)
	return err
}

func (c *MasterClient) PollTasks(ctx context.Context, batch int) ([]TaskMessage, error) {
	path := fmt.Sprintf("/agent-api/tasks/poll?batch=%d&timeout=30s", batch)
	data, err := c.doJSON(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Tasks []TaskMessage `json:"tasks"`
		Count int           `json:"count"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse tasks: %w", err)
	}

	return resp.Tasks, nil
}

func (c *MasterClient) ReportResult(ctx context.Context, result *TaskResult) error {
	_, err := c.doJSON(ctx, "POST", "/agent-api/tasks/result", result)
	if err != nil {
		slog.Error("report result failed",
			"execution_id", result.ExecutionID,
			"error", err)
	}
	return err
}

func (c *MasterClient) GetRules(ctx context.Context) (map[string]json.RawMessage, error) {
	data, err := c.doJSON(ctx, "GET", "/agent-api/rules", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return resp.Rules, nil
}

func (c *MasterClient) PollCommands(ctx context.Context) ([]json.RawMessage, error) {
	data, err := c.doJSON(ctx, "GET", "/agent-api/commands/poll?timeout=30s", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Commands []json.RawMessage `json:"commands"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return resp.Commands, nil
}

type HeartbeatReq struct {
	RunningTasks  int     `json:"running_tasks"`
	QueuedTasks   int     `json:"queued_tasks"`
	MaxConcurrent int     `json:"max_concurrent"`
	MaxQueue      int     `json:"max_queue"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	Version       string  `json:"version"`
	MacAddress    string  `json:"mac_address"`
	IPAddress     string  `json:"ip_address"`
}
