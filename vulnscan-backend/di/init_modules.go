package di

import (
	"context"
	"log/slog"
	"os"

	"code.yt-security.com/public/scanengine/module/cyberspace"
	"vulnscan-backend/asm"
	"vulnscan-backend/boot"
	"vulnscan-backend/cluster"
	"vulnscan-backend/cluster/ws"
	"vulnscan-backend/cyberquery"
	fedAuth "vulnscan-backend/federation/auth"
	fedClient "vulnscan-backend/federation/client"
	"vulnscan-backend/federation/server"
	"vulnscan-backend/intel"
	"vulnscan-backend/knowledge/aihub"
	"vulnscan-backend/knowledge/datalib"
	kfp "vulnscan-backend/knowledge/fingerprint"
	"vulnscan-backend/knowledge/poc"
	kproduct "vulnscan-backend/knowledge/product"
	kprompt "vulnscan-backend/knowledge/prompt"
	"vulnscan-backend/model"
	"vulnscan-backend/nodeapi"
	"vulnscan-backend/pkg/clusterconn"
	"vulnscan-backend/scanrunner"
	"vulnscan-backend/schedule"
	"vulnscan-backend/setting"
	tmplAPI "vulnscan-backend/template/api"

	"code.yt-security.com/public/access/authorize"
	"github.com/gin-gonic/gin"
)

func (h *Handlers) initSettings() {
	svc := setting.NewServiceSetting(h.DB)
	h.Settings = setting.NewHandler(svc)
	h.Settings.SeedDefaults()
	slog.Info("[+] 系统设置模块已初始化")
}

func (h *Handlers) initScheduler(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Scheduler] 获取数据库会话失败", "error", err)
		return
	}

	h.sched = scanrunner.New(session, 10)
	if h.Incident != nil {
		eb := scanrunner.NewEventBridge(
			session,
			h.Incident.CoreService(),
			h.Circular.TransferService(),
			scanrunner.DefaultEventBridgeConfig(),
		)
		h.sched.SetEventBridge(eb)
		slog.Info("[+] 扫描完成自动转安全事件已启用")
	}
	h.sched.Start(context.Background())

	scanAPI := scanrunner.NewAPI(session, h.sched)
	*backends = append(*backends, scanAPI.RoutesWithGroup(authGroup)...)

	reportAPI := scanrunner.NewReportAPI(session)
	reportAPI.RegisterRoutes(authGroup)

	pipelineAPI := scanrunner.NewPipelineAPI(session)
	*backends = append(*backends, pipelineAPI.RoutesWithGroup(authGroup)...)

	h.Asset.BindScanRunner(session, h.sched)
	if h.Vuln != nil {
		h.Vuln.BindScanRunner(session, h.sched)
	}

	slog.Info("[+] Scheduler + Report + Pipeline API 已注册")
}

func (h *Handlers) initCronScheduler(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Cron] 获取数据库会话失败", "error", err)
		return
	}

	schedSvc := schedule.NewServiceSchedule(h.DB)
	schedHandler := schedule.NewHandler(schedSvc)
	schedRoutes := schedule.NewSchedule(schedHandler)
	*backends = append(*backends, schedRoutes.RoutesWithGroup(authGroup)...)

	h.cronRunner = schedule.NewCronRunner(session, h.sched)
	schedHandler.SetCronRunner(h.cronRunner)
	h.cronRunner.Start(context.Background())

	slog.Info("[+] 定时调度 API + Cron Runner 已注册")
}

func (h *Handlers) initKnowledgeAPIs(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Knowledge] 获取数据库会话失败", "error", err)
		return
	}

	_ = session.AutoMigrate(&model.DataLibrary{}, &model.DataLibraryEntry{})

	h.Knowledge = scanrunner.NewKnowledgeRegistry(session)
	scanrunner.SetDefaultKnowledgeRegistry(h.Knowledge)
	h.payloadLoader = h.Knowledge.RawLoader

	pocSvc := poc.NewServicePoc(h.DB, h.Knowledge.Poc)
	pocHandler := poc.NewHandlerPoc(pocSvc)
	pocRoutes := poc.NewPoc(pocHandler)
	*backends = append(*backends, pocRoutes.RoutesWithGroup(authGroup)...)

	fpSvc := kfp.NewServiceFingerprint(h.DB)
	fpHandler := kfp.NewHandlerFingerprint(fpSvc)
	webFpSvc := kfp.NewServiceWebFingerprint(h.DB)
	webFpHandler := kfp.NewHandlerWebFingerprint(webFpSvc)
	fpRoutes := kfp.NewFingerprintFull(fpHandler, webFpHandler)
	*backends = append(*backends, fpRoutes.RoutesWithGroup(authGroup)...)

	dlSvc := datalib.NewServiceDataLib(h.DB)
	dlHandler := datalib.NewHandlerDataLib(dlSvc, h.Knowledge)
	dlRoutes := datalib.NewDataLib(dlHandler)
	*backends = append(*backends, dlRoutes.RoutesWithGroup(authGroup)...)

	promptSvc := kprompt.NewService(h.DB)
	promptHandler := kprompt.NewHandler(promptSvc)
	promptRoutes := kprompt.NewPrompt(promptHandler)
	*backends = append(*backends, promptRoutes.RoutesWithGroup(authGroup)...)

	kprompt.SeedBuiltinTemplates(session)

	productSvc := kproduct.NewServiceProduct(h.DB)
	productHandler := kproduct.NewHandlerProduct(productSvc)
	productRoutes := kproduct.NewProductRoutes(productHandler)
	*backends = append(*backends, productRoutes.RoutesWithGroup(authGroup)...)
	kproduct.SeedBuiltinProducts(session)

	if h.Knowledge != nil && h.Knowledge.Poc != nil {
		h.Knowledge.Poc.SetProductLinker(productSvc)
	}
	webFpSvc.SetProductLinker(productSvc)

	aiHub := aihub.NewHub(h.IAM.AI, "")
	aiHandler := aihub.NewHandler(aiHub)
	aiRoutes := aihub.NewRoutes(aiHandler)
	*backends = append(*backends, aiRoutes.RoutesWithGroup(authGroup)...)

	slog.Info("[+] POC + Fingerprint + DataLib + PromptTemplate + Product + AIFingerprint 知识库 API 已注册")
}

func (h *Handlers) initTemplateAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Template] 获取数据库会话失败", "error", err)
		return
	}

	handler := tmplAPI.NewHandler(session)
	routes := tmplAPI.NewTemplate(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)

	h.seedBuiltinTemplates(session)
	slog.Info("[+] Template API 已注册")
}

func (h *Handlers) initCyberspaceAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	providers := []string{"fofa", "hunter", "shodan"}
	configs := make(map[string]cyberspace.ProviderConfig)
	for _, name := range providers {
		prefix := "cyberspace." + name + "."
		if h.Settings.GetBool(prefix+"enabled", false) {
			configs[name] = cyberspace.ProviderConfig{
				APIKey:    h.Settings.Get(prefix+"api_key", ""),
				BaseURL:   h.Settings.Get(prefix+"base_url", ""),
				Enabled:   true,
				RateLimit: h.Settings.GetInt(prefix+"rate_limit", 5),
			}
		}
	}
	handler := cyberquery.NewHandler(configs)
	routes := cyberquery.NewCyberQuery(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] Cyberspace Query API 已注册")
}

func (h *Handlers) initASMAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[ASM] 获取数据库会话失败", "error", err)
		return
	}

	var collectors []asm.AssetCollector
	cyberConfigs := h.getCyberspaceConfigs()
	if len(cyberConfigs) > 0 {
		collectors = append(collectors, asm.NewCyberspaceCollector(cyberConfigs))
	}
	collectors = append(collectors, asm.NewPortExposureCollector(session))
	collectors = append(collectors, asm.NewSubdomainBruteCollector(nil, 0, 0))
	collectors = append(collectors, asm.NewPortScanCollector(nil, 0, 0))
	collectors = append(collectors, asm.NewServiceFingerprintCollector(0))

	svc := asm.NewServiceASM(h.DB)
	handler := asm.NewHandler(svc, collectors...)
	routes := asm.NewASM(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] ASM 攻击面管理 API 已注册", "cyberspace_providers", len(cyberConfigs))
}

func (h *Handlers) initIntelAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Intel] 获取数据库会话失败", "error", err)
		return
	}
	handler := intel.NewHandler(session)
	handler.StartSync(context.Background())
	routes := intel.NewIntel(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] 威胁情报 API 已注册")
}

func (h *Handlers) initWebSocket(apiGroup *gin.RouterGroup) {
	h.wsHub = h.initWSHub()
	wsHandler := ws.NewWSHandler(h.wsHub)
	wsHandler.RegisterRoutes(apiGroup)
	slog.Info("[+] WebSocket Hub 已启动")
}

func (h *Handlers) initWSHub() *ws.Hub {
	svc := cluster.NewServiceClusterForWS(h.DB, clusterconn.OptionsFromConfig(h.Config))
	hub := ws.NewHub(svc)
	go hub.Run()
	return hub
}

func (h *Handlers) initUnifiedNodes(authGroup *gin.RouterGroup) []authorize.BackendItem {
	session, err := h.DB.GetDBSession()
	if err != nil {
		return nil
	}
	return cluster.RegisterUnifiedNodeRoutes(authGroup, session, h.sched)
}

func (h *Handlers) initFederationManageAPI(authGroup *gin.RouterGroup) []authorize.BackendItem {
	session, err := h.DB.GetDBSession()
	if err != nil {
		return nil
	}
	return server.RegisterManageRoutes(authGroup, session)
}

func (h *Handlers) initFederation() {
	if !h.Settings.GetBool("federation.enabled", false) {
		return
	}

	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Federation] 获取数据库会话失败", "error", err)
		return
	}

	if secret := os.Getenv("FEDERATION_SECRET"); secret != "" {
		fedAuth.SetFederationSecret(secret)
	}

	mode := h.Settings.Get("scanner.mode", "standalone")

	switch mode {
	case "central":
		ginEngine := h.Web.Engine
		server.RegisterRoutes(ginEngine, session)
		slog.Info("[Federation] Central Master Federation Server 已启动")

		session.AutoMigrate(
			&model.FederationTenant{},
			&model.SubMaster{},
			&model.FederationLicense{},
			&model.SyncVersion{},
			&model.SyncLog{},
			&model.AggregateVuln{},
			&model.AggregateScan{},
		)

	case "sub-master":
		centralURL := h.Settings.Get("federation.upstream.central_url", "")
		if centralURL == "" {
			slog.Warn("[Federation] sub-master 模式需要配置 federation.upstream.central_url")
			return
		}
		upstreamCfg := boot.FederationUpstreamConfig{
			CentralURL:       centralURL,
			APIToken:         h.Settings.Get("federation.upstream.api_token", ""),
			TLSCert:          h.Settings.Get("federation.upstream.tls_cert", ""),
			TLSKey:           h.Settings.Get("federation.upstream.tls_key", ""),
			CACert:           h.Settings.Get("federation.upstream.ca_cert", ""),
			LicenseFile:      h.Settings.Get("federation.upstream.license_file", ""),
			SyncInterval:     h.Settings.Get("federation.upstream.sync_interval", "10m"),
			ReportInterval:   h.Settings.Get("federation.upstream.report_interval", "5m"),
			OfflineGraceDays: h.Settings.GetInt("federation.upstream.offline_grace_days", 30),
		}
		h.fedClient = fedClient.New(upstreamCfg, session)
		if startErr := h.fedClient.Start(); startErr != nil {
			slog.Error("[Federation] 联邦客户端启动失败", "error", startErr)
		} else {
			slog.Info("[Federation] Sub-Master Federation Client 已启动")
		}

	default:
		slog.Debug("[Federation] 模式不需要联邦功能", "mode", mode)
	}
}

func (h *Handlers) getCyberspaceConfigs() map[string]cyberspace.ProviderConfig {
	providers := []string{"fofa", "hunter", "shodan", "zoomeye", "censys"}
	configs := make(map[string]cyberspace.ProviderConfig)
	for _, name := range providers {
		prefix := "cyberspace." + name + "."
		if h.Settings.GetBool(prefix+"enabled", false) {
			configs[name] = cyberspace.ProviderConfig{
				APIKey:    h.Settings.Get(prefix+"api_key", ""),
				APISecret: h.Settings.Get(prefix+"api_secret", ""),
				BaseURL:   h.Settings.Get(prefix+"base_url", ""),
				Enabled:   true,
				RateLimit: h.Settings.GetInt(prefix+"rate_limit", 5),
			}
		}
	}
	return configs
}

func (h *Handlers) initNodeAPI(engine *gin.Engine) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("nodeapi: DB session error", "error", err)
		return
	}

	_ = session.AutoMigrate(&model.Node{})

	monitorHandler := nodeapi.NewDBMonitorResultHandler(session)
	scanHandler := nodeapi.NewDBScanResultHandler(session)
	opts := nodeapi.OptionsFromEnv()
	api := nodeapi.New(h.DB, monitorHandler, scanHandler, opts)
	api.RegisterRoutes(engine, h.Config.IAM.PathPrefix)

	if opts.RequireAgentSecret {
		slog.Warn("[+] Node API 已启用 VULNSCAN_NODEAPI_REQUIRE_AGENT_SECRET：所有节点必须在库中配置 agent_secret_hash，否则将返回 403")
	}
	slog.Info("[+] Node API 已注册", "prefix", h.Config.IAM.PathPrefix+"/node-api")
}
