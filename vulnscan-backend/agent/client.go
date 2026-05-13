package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
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

func (c *Client) Heartbeat(ctx context.Context, hb *HeartbeatReq) error {
	_, err := c.doJSON(ctx, "POST", "/node-api/heartbeat", hb)
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

	var resp struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
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
