package traffic

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/lyserver"
	"vulnscan-backend/traffic/internal/mq"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/socketio"
	"vulnscan-backend/traffic/internal/store"
	"vulnscan-backend/traffic/internal/worker"

	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

// Traffic is the DeepSOC/traffic-analysis business module mounted into the
// IAM backend template. Its original compatibility APIs are exposed under
// /api business routes while the legacy HTTP kernel remains the execution
// engine behind the handlers.
type Traffic struct {
	api   *Handler
	queue mq.Queue
}

type Config struct {
	StoreBackend            string `json:"store_backend" toml:"store_backend"`
	DatabaseURL             string `json:"database_url" toml:"database_url"`
	AutoMigrate             bool   `json:"auto_migrate" toml:"auto_migrate"`
	InternalAPIKey          string `json:"internal_api_key" toml:"internal_api_key"`
	FlowShadowBaseURL       string `json:"flowshadow_base_url" toml:"flowshadow_base_url"`
	FlowShadowAPIKey        string `json:"flowshadow_api_key" toml:"flowshadow_api_key"`
	DeepSOCBaseURL          string `json:"deepsoc_base_url" toml:"deepsoc_base_url"`
	DeepSOCUsername         string `json:"deepsoc_username" toml:"deepsoc_username"`
	DeepSOCPassword         string `json:"deepsoc_password" toml:"deepsoc_password"`
	DeepSOCAPIKey           string `json:"deepsoc_api_key" toml:"deepsoc_api_key"`
	CircularBaseURL         string `json:"circular_base_url" toml:"circular_base_url"`
	LLMBaseURL              string `json:"llm_base_url" toml:"llm_base_url"`
	LLMAPIKey               string `json:"llm_api_key" toml:"llm_api_key"`
	LLMModel                string `json:"llm_model" toml:"llm_model"`
	LLMTimeoutSeconds       int    `json:"llm_timeout_seconds" toml:"llm_timeout_seconds"`
	SyncBatchSize           int    `json:"sync_batch_size" toml:"sync_batch_size"`
	SyncLookbackSeconds     int    `json:"sync_lookback_seconds" toml:"sync_lookback_seconds"`
	SyncMaxRetries          int    `json:"sync_max_retries" toml:"sync_max_retries"`
	HTTPTimeoutSeconds      int    `json:"http_timeout_seconds" toml:"http_timeout_seconds"`
	MQBackend               string `json:"mq_backend" toml:"mq_backend"`
	RabbitMQURL             string `json:"rabbitmq_url" toml:"rabbitmq_url"`
	RabbitMQExchange        string `json:"rabbitmq_exchange" toml:"rabbitmq_exchange"`
	RabbitMQEventQueue      string `json:"rabbitmq_event_queue" toml:"rabbitmq_event_queue"`
	RabbitMQConsumerEnabled bool   `json:"rabbitmq_consumer_enabled" toml:"rabbitmq_consumer_enabled"`
}

func NewTraffic(moduleCfg Config) *Traffic {
	cfg := moduleCfg.toInternal()
	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	llmHTTPClient := &http.Client{Timeout: cfg.LLMTimeout}

	st := loadStore(cfg)
	queue := loadQueue(cfg, st)

	services := service.Services{
		Store: st,
		DeepSOC: client.DeepSOCClient{
			BaseURL:  cfg.DeepSOCBaseURL,
			APIKey:   cfg.DeepSOCAPIKey,
			Username: cfg.DeepSOCUsername,
			Password: cfg.DeepSOCPassword,
			HTTP:     httpClient,
		},
		FlowShadow: client.FlowShadowClient{
			BaseURL: cfg.FlowShadowBaseURL,
			APIKey:  cfg.FlowShadowAPIKey,
			HTTP:    httpClient,
		},
		Circular: client.CircularClient{
			BaseURL: cfg.CircularBaseURL,
			HTTP:    httpClient,
		},
		LLM: &client.LLMClient{
			BaseURL: cfg.LLMBaseURL,
			APIKey:  cfg.LLMAPIKey,
			Model:   cfg.LLMModel,
			HTTP:    llmHTTPClient,
		},
		Queue: queue,
	}

	socketHub := socketio.NewHub()
	return &Traffic{
		api: NewHandler(
			NewEventService(services),
			NewAssetService(st),
			NewAccountService(services),
			NewChatService(services),
			NewSystemService(cfg, services),
			NewInternalService(cfg, services),
			lyserver.New(cfg.DatabaseURL),
			socketHub,
		),
		queue: queue,
	}
}

func loadStore(cfg config.Config) store.Store {
	switch strings.ToLower(cfg.StoreBackend) {
	case "postgres":
		pg, err := store.NewPostgresStore(context.Background(), cfg.DatabaseURL, cfg.AutoMigrate)
		if err != nil {
			log.Printf("traffic: init postgres store failed, falling back to memory: %v", err)
			return store.NewMemoryStore()
		}
		return pg
	default:
		return store.NewMemoryStore()
	}
}

func (c Config) toInternal() config.Config {
	cfg := config.Load()
	if c.StoreBackend != "" {
		cfg.StoreBackend = strings.ToLower(c.StoreBackend)
	}
	if c.DatabaseURL != "" {
		cfg.DatabaseURL = c.DatabaseURL
	}
	cfg.AutoMigrate = c.AutoMigrate
	if c.InternalAPIKey != "" {
		cfg.InternalAPIKey = c.InternalAPIKey
	}
	if c.FlowShadowBaseURL != "" {
		cfg.FlowShadowBaseURL = c.FlowShadowBaseURL
	}
	if c.FlowShadowAPIKey != "" {
		cfg.FlowShadowAPIKey = c.FlowShadowAPIKey
	}
	if c.DeepSOCBaseURL != "" {
		cfg.DeepSOCBaseURL = c.DeepSOCBaseURL
	}
	if c.DeepSOCUsername != "" {
		cfg.DeepSOCUsername = c.DeepSOCUsername
	}
	if c.DeepSOCPassword != "" {
		cfg.DeepSOCPassword = c.DeepSOCPassword
	}
	if c.DeepSOCAPIKey != "" {
		cfg.DeepSOCAPIKey = c.DeepSOCAPIKey
	}
	if c.CircularBaseURL != "" {
		cfg.CircularBaseURL = c.CircularBaseURL
	}
	if c.LLMBaseURL != "" {
		cfg.LLMBaseURL = c.LLMBaseURL
	}
	if c.LLMAPIKey != "" {
		cfg.LLMAPIKey = c.LLMAPIKey
	}
	if c.LLMModel != "" {
		cfg.LLMModel = c.LLMModel
	}
	if c.LLMTimeoutSeconds > 0 {
		cfg.LLMTimeout = time.Duration(c.LLMTimeoutSeconds) * time.Second
	}
	if c.SyncBatchSize > 0 {
		cfg.SyncBatchSize = c.SyncBatchSize
	}
	if c.SyncLookbackSeconds > 0 {
		cfg.SyncLookbackSeconds = c.SyncLookbackSeconds
	}
	if c.SyncMaxRetries > 0 {
		cfg.SyncMaxRetries = c.SyncMaxRetries
	}
	if c.HTTPTimeoutSeconds > 0 {
		cfg.HTTPTimeout = time.Duration(c.HTTPTimeoutSeconds) * time.Second
	}
	if c.MQBackend != "" {
		cfg.MQBackend = strings.ToLower(c.MQBackend)
	}
	if c.RabbitMQURL != "" {
		cfg.RabbitMQURL = c.RabbitMQURL
	}
	if c.RabbitMQExchange != "" {
		cfg.RabbitMQExchange = c.RabbitMQExchange
	}
	if c.RabbitMQEventQueue != "" {
		cfg.RabbitMQEventQueue = c.RabbitMQEventQueue
	}
	cfg.RabbitMQConsumerEnabled = c.RabbitMQConsumerEnabled
	return cfg
}

func loadQueue(cfg config.Config, st store.Store) mq.Queue {
	if strings.ToLower(cfg.MQBackend) != "rabbitmq" {
		return mq.NoopQueue{}
	}
	rabbit, err := mq.NewRabbitMQ(context.Background(), mq.RabbitConfig{
		URL:      cfg.RabbitMQURL,
		Exchange: cfg.RabbitMQExchange,
		Queue:    cfg.RabbitMQEventQueue,
	})
	if err != nil {
		log.Printf("traffic: init rabbitmq failed, using noop queue: %v", err)
		return mq.NoopQueue{}
	}
	worker.StartRabbitEventWorker(context.Background(), cfg, st)
	return rabbit
}

func (m *Traffic) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	var all []authorize.BackendItem

	all = append(all, authorize.RegisterRoutes(e.Group("/dashboard"), []authorize.Route{
		{
			Name:    "流量分析统计看板",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "服务状态", Path: "health", Method: "GET", Handler: m.api.Health, Enabled: true},
				{Name: "LLM状态", Path: "llm-health", Method: "GET", Handler: m.api.LLMHealth, Enabled: true},
				{Name: "LLM配置", Path: "llm-config", Method: "GET", Handler: m.api.LLMConfig, Enabled: true},
				{Name: "保存LLM配置", Path: "llm-config", Method: "PUT", Handler: m.api.LLMConfig, Enabled: true},
				{Name: "版本信息", Path: "version", Method: "GET", Handler: m.api.Version, Enabled: true},
				{Name: "全局报告", Path: "report/global", Method: "POST", Handler: m.api.ReportGlobal, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/deepsoc/auth"), []authorize.Route{
		{
			Name:    "DeepSOC认证",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "登录", Path: "login", Method: "POST", Handler: m.api.DeepSOCAuthLogin, Enabled: true},
				{Name: "退出", Path: "logout", Method: "POST", Handler: m.api.DeepSOCAuthLogout, Enabled: true},
				{Name: "当前用户", Path: "me", Method: "GET", Handler: m.api.DeepSOCAuthMe, Enabled: true},
				{Name: "认证检查", Path: "check-auth", Method: "GET", Handler: m.api.DeepSOCCheckAuth, Enabled: true},
				{Name: "初始化管理员", Path: "init-admin", Method: "POST", Handler: m.api.DeepSOCInitAdmin, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/events"), []authorize.Route{
		{
			Name:    "流量安全事件",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "创建事件", Method: "POST", Handler: m.api.CreateEvent, Enabled: true},
				{Name: "事件列表", Path: "list", Method: "GET", Handler: m.api.ListEvents, Enabled: true},
				{Name: "事件详情", Path: "detail/:eventID", Method: "GET", Handler: m.api.GetEvent, Enabled: true},
				{Name: "事件消息", Path: "detail/:eventID/messages", Method: "GET", Handler: m.api.EventMessages, Enabled: true},
				{Name: "事件任务", Path: "detail/:eventID/tasks", Method: "GET", Handler: m.api.EventTasks, Enabled: true},
				{Name: "事件动作", Path: "detail/:eventID/actions", Method: "GET", Handler: m.api.EventActions, Enabled: true},
				{Name: "事件命令", Path: "detail/:eventID/commands", Method: "GET", Handler: m.api.EventCommands, Enabled: true},
				{Name: "事件统计", Path: "detail/:eventID/stats", Method: "GET", Handler: m.api.EventStats, Enabled: true},
				{Name: "事件总结", Path: "detail/:eventID/summaries", Method: "GET", Handler: m.api.EventSummaries, Enabled: true},
				{Name: "发送消息", Path: "detail/:eventID/messages", Method: "POST", Handler: m.api.SendEventMessage, Enabled: true},
				{Name: "执行记录", Path: "detail/:eventID/executions", Method: "GET", Handler: m.api.EventExecutions, Enabled: true},
				{Name: "完成执行", Path: "detail/:eventID/executions/:executionID/complete", Method: "POST", Handler: m.api.CompleteExecution, Enabled: true},
				{Name: "事件层级", Path: "detail/:eventID/hierarchy", Method: "GET", Handler: m.api.EventHierarchy, Enabled: true},
				{Name: "事件审核", Path: "detail/:eventID/review", Method: "POST", Handler: m.api.ReviewEvent, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/assets"), []authorize.Route{
		{
			Name:    "流量资产管理",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "资产列表", Path: "list", Method: "GET", Handler: m.api.ListAssets, Enabled: true},
				{Name: "创建资产", Method: "POST", Handler: m.api.CreateAsset, Enabled: true},
				{Name: "更新资产", Path: ":id", Method: "PUT", Handler: m.api.UpdateAsset, Enabled: true},
				{Name: "删除资产", Path: ":id", Method: "DELETE", Handler: m.api.DeleteAsset, Enabled: true},
				{Name: "导入资产", Path: "import", Method: "POST", Handler: m.api.ImportAssets, Enabled: true},
				{Name: "导入模板", Path: "import/template", Method: "GET", Handler: m.api.AssetImportTemplate, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/users"), []authorize.Route{
		{
			Name:    "DeepSOC用户管理",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "用户列表", Path: "list", Method: "GET", Handler: m.api.Users, Enabled: true},
				{Name: "创建用户", Method: "POST", Handler: m.api.UserCreate, Enabled: true},
				{Name: "用户详情", Path: "detail/:userID", Method: "GET", Handler: m.api.UserDetail, Enabled: true},
				{Name: "更新用户", Path: "detail/:userID", Method: "PUT", Handler: m.api.UserDetail, Enabled: true},
				{Name: "删除用户", Path: "detail/:userID", Method: "DELETE", Handler: m.api.UserDetail, Enabled: true},
				{Name: "修改密码", Path: "detail/:userID/password", Method: "PUT", Handler: m.api.UserPassword, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/prompts"), []authorize.Route{
		{
			Name:    "提示词配置",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "提示词列表", Path: "list", Method: "GET", Handler: m.api.PromptList, Enabled: true},
				{Name: "提示词详情", Path: "detail/:role", Method: "GET", Handler: m.api.PromptRole, Enabled: true},
				{Name: "提示词更新", Path: "detail/:role", Method: "PUT", Handler: m.api.PromptRole, Enabled: true},
				{Name: "背景详情", Path: "background/:name", Method: "GET", Handler: m.api.PromptBackground, Enabled: true},
				{Name: "背景更新", Path: "background/:name", Method: "PUT", Handler: m.api.PromptBackground, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/state"), []authorize.Route{
		{
			Name:    "运行状态",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "自动分析状态", Path: "driving-mode", Method: "GET", Handler: m.api.DrivingMode, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/engineer-chat"), []authorize.Route{
		{
			Name:    "工程师会话",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "发送消息", Path: "send", Method: "POST", Handler: m.api.EngineerChatSend, Enabled: true},
				{Name: "历史记录", Path: "history", Method: "GET", Handler: m.api.EngineerChatHistory, Enabled: true},
				{Name: "新建会话", Path: "new-session", Method: "POST", Handler: m.api.EngineerChatNewSession, Enabled: true},
				{Name: "会话状态", Path: "status", Method: "GET", Handler: m.api.EngineerChatStatus, Enabled: true},
			},
		},
	})...)

	all = append(all, authorize.RegisterRoutes(e.Group("/ly"), []authorize.Route{
		{
			Name:    "流量分析兼容配置",
			Enabled: true,
			Children: []authorize.Route{
				{Name: "兼容GET接口", Path: "/*path", Method: "GET", Handler: m.api.Ly, Enabled: true},
				{Name: "兼容POST接口", Path: "/*path", Method: "POST", Handler: m.api.Ly, Enabled: true},
			},
		},
	})...)

	return all
}

func (m *Traffic) PublicRoutes(e *gin.RouterGroup) {
	e.GET("/healthz", m.api.Health)
	e.GET("/health", m.api.Health)
	e.GET("/health/llm", m.api.LLMHealth)
	e.GET("/llm/config", m.api.LLMConfig)
	e.POST("/llm/config", m.api.LLMConfig)
	e.PUT("/llm/config", m.api.LLMConfig)
	e.POST("/internal/*path", m.api.Internal)
	e.GET("/internal/*path", m.api.Internal)
	e.PUT("/internal/*path", m.api.Internal)
	e.DELETE("/internal/*path", m.api.Internal)
	e.Any("/socket.io", m.api.SocketIO)
	e.Any("/socket.io/*path", m.api.SocketIO)
}

func (m *Traffic) Shutdown() {
	if m.queue != nil {
		_ = m.queue.Close()
	}
}
