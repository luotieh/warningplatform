package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	token      string
	secret     string
	httpClient *http.Client
}

func NewClient(baseURL, token, secret string) *Client {
	return &Client{
		baseURL: trimMasterURL(baseURL),
		token:   token,
		secret:  strings.TrimSpace(secret),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", c.token)
	if c.secret != "" {
		req.Header.Set("X-Agent-Secret", c.secret)
	}
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
		return respBody, fmt.Errorf("HTTP %d: %s", resp.StatusCode, FormatHTTPErrorBody(respBody))
	}
	if err := assertJSONResponse(respBody); err != nil {
		return respBody, err
	}

	return respBody, nil
}

func assertJSONResponse(body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	if trimmed[0] == '<' {
		return fmt.Errorf("主控返回了 HTML 而非 JSON（请确认 master_url 含 /api 后缀，例如 http://127.0.0.1:8090/api）")
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return fmt.Errorf("主控返回了非 JSON 响应（请确认 master_url 指向 vulnscan 后端 API 根路径）")
	}
	return nil
}

// PingHealth 探测主控 node-api 是否可达（无需鉴权）。
func (c *Client) PingHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.baseURL, "/")+"/node-api/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, FormatHTTPErrorBody(body))
	}
	if err := assertJSONResponse(body); err != nil {
		return err
	}
	var probe struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || !probe.OK {
		return fmt.Errorf("node-api 健康检查未通过（请确认 master_url=%s 且主控已启动）", c.baseURL)
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, hb *HeartbeatReq) error {
	_, err := c.doJSON(ctx, "POST", "/node-api/heartbeat", hb)
	return err
}

// Shutdown 通知主控本节点即将/已经停止运行（优雅退出）。
func (c *Client) Shutdown(ctx context.Context, req *ShutdownReq) error {
	_, err := c.doJSON(ctx, "POST", "/node-api/shutdown", req)
	return err
}

func (c *Client) PollTasks(ctx context.Context, batch int) ([]TaskEnvelope, error) {
	path := fmt.Sprintf("/node-api/tasks/poll?batch=%d&timeout=30s", batch)
	data, err := c.doJSON(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Tasks []TaskEnvelope `json:"tasks"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse tasks: %w", err)
	}

	return resp.Tasks, nil
}

func (c *Client) ReportResult(ctx context.Context, result *TaskResult) error {
	_, err := c.doJSON(ctx, "POST", "/node-api/tasks/result", result)
	return err
}

func (c *Client) GetRules(ctx context.Context) (map[string]json.RawMessage, error) {
	data, err := c.doJSON(ctx, "GET", "/node-api/rules", nil)
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return map[string]json.RawMessage{}, nil
	}

	var resp struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if resp.Rules == nil {
		return map[string]json.RawMessage{}, nil
	}

	return resp.Rules, nil
}

func (c *Client) PollCommands(ctx context.Context) ([]json.RawMessage, error) {
	data, err := c.doJSON(ctx, "GET", "/node-api/commands/poll?timeout=30s", nil)
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
