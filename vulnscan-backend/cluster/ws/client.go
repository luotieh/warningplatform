package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client is the WebSocket client that a Worker uses to connect to Master.
type Client struct {
	masterURL string
	workerID  string
	conn      *websocket.Conn
	mu        sync.Mutex
	sendCh    chan []byte
	recvCh    chan *Envelope
	ctx       context.Context
	cancel    context.CancelFunc
	connected bool

	OnTaskAssign   func(TaskAssignPayload)
	OnCommand      func(Command)
	OnHeartbeatAck func(HeartbeatAckPayload)
}

func NewClient(masterURL, workerID string) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		masterURL: masterURL,
		workerID:  workerID,
		sendCh:    make(chan []byte, 64),
		recvCh:    make(chan *Envelope, 64),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Connect establishes the WebSocket connection with auto-reconnect.
func (c *Client) Connect() error {
	if err := c.dial(); err != nil {
		return err
	}

	go c.readLoop()
	go c.writeLoop()
	go c.reconnectLoop()

	return nil
}

func (c *Client) dial() error {
	u, err := url.Parse(c.masterURL)
	if err != nil {
		return err
	}

	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	wsURL := scheme + "://" + u.Host + u.Path + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.connected = true
	c.mu.Unlock()

	slog.Info("[WSClient] 已连接到 Master", "url", wsURL)
	return nil
}

func (c *Client) Close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connected = false
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Send sends a typed message to Master.
func (c *Client) Send(msgType string, data interface{}) error {
	env, err := NewEnvelope(msgType, data)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}

	select {
	case c.sendCh <- raw:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

func (c *Client) Register(payload RegisterPayload) error {
	return c.Send(MsgTypeRegister, payload)
}

func (c *Client) SendHeartbeat(payload HeartbeatPayload) error {
	return c.Send(MsgTypeHeartbeat, payload)
}

func (c *Client) PollTask(slots int) error {
	return c.Send(MsgTypePollTask, PollTaskPayload{
		WorkerID: c.workerID,
		Slots:    slots,
	})
}

func (c *Client) ReportProgress(payload TaskProgressPayload) error {
	return c.Send(MsgTypeTaskProgress, payload)
}

func (c *Client) ReportResult(payload TaskResultPayload) error {
	return c.Send(MsgTypeTaskResult, payload)
}

func (c *Client) ReportBan(payload BanReportPayload) error {
	return c.Send(MsgTypeBanReport, payload)
}

func (c *Client) readLoop() {
	defer func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()

		if conn == nil {
			time.Sleep(time.Second)
			continue
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			slog.Warn("[WSClient] 读取失败，准备重连", "error", err)
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return
		}

		var env Envelope
		if err := json.Unmarshal(message, &env); err != nil {
			continue
		}

		c.handleMessage(&env)
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case msg := <-c.sendCh:
			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()

			if conn == nil {
				continue
			}

			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				slog.Warn("[WSClient] 写入失败", "error", err)
			}
		}
	}
}

func (c *Client) reconnectLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(5 * time.Second):
			if !c.IsConnected() {
				slog.Info("[WSClient] 尝试重新连接...")
				if err := c.dial(); err != nil {
					slog.Warn("[WSClient] 重连失败", "error", err)
					continue
				}
				go c.readLoop()

				c.Register(RegisterPayload{WorkerID: c.workerID})
			}
		}
	}
}

func (c *Client) handleMessage(env *Envelope) {
	switch env.Type {
	case MsgTypeRegisterAck:
		var ack RegisterAckPayload
		json.Unmarshal(env.Data, &ack)
		if ack.OK {
			slog.Info("[WSClient] 注册确认成功")
		}

	case MsgTypeHeartbeatAck:
		var ack HeartbeatAckPayload
		json.Unmarshal(env.Data, &ack)
		if c.OnHeartbeatAck != nil {
			c.OnHeartbeatAck(ack)
		}

	case MsgTypeTaskAssign:
		var task TaskAssignPayload
		if err := json.Unmarshal(env.Data, &task); err != nil {
			return
		}
		if c.OnTaskAssign != nil {
			c.OnTaskAssign(task)
		}

	case MsgTypeCommand:
		var cmd Command
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			return
		}
		if c.OnCommand != nil {
			c.OnCommand(cmd)
		}

	case MsgTypeTaskResultAck:
		slog.Debug("[WSClient] 结果上报确认")

	case MsgTypePing:
		c.Send(MsgTypePong, nil)

	default:
		slog.Debug("[WSClient] 未知消息", "type", env.Type)
	}
}
