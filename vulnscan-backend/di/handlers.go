package di

import (
	"context"
	"log/slog"
	"os"
	"time"

	"encoding/json"
	"vulnscan-backend/asm"
	"vulnscan-backend/asset"
	"vulnscan-backend/assetmgr"
	"vulnscan-backend/boot"
	"vulnscan-backend/circular"
	"vulnscan-backend/cluster"
	"vulnscan-backend/cluster/ws"
	"vulnscan-backend/compliance"
	"vulnscan-backend/cyberquery"
	"vulnscan-backend/dashboard"
	fedAuth "vulnscan-backend/federation/auth"
	fedClient "vulnscan-backend/federation/client"
	"vulnscan-backend/federation/server"
	"vulnscan-backend/frontend"
	"vulnscan-backend/health"
	"vulnscan-backend/incident"
	"vulnscan-backend/intel"
	kdict "vulnscan-backend/knowledge/dict"
	kfp "vulnscan-backend/knowledge/fingerprint"
	"vulnscan-backend/migration"
	"vulnscan-backend/model"
	"vulnscan-backend/monitoragent"
	"vulnscan-backend/notify"
	"vulnscan-backend/nuclei"
	"vulnscan-backend/organize"
	"vulnscan-backend/poc"
	"vulnscan-backend/scan/module/cyberspace"
	"vulnscan-backend/schedule"
	"vulnscan-backend/scheduler"
	"vulnscan-backend/setting"
	"vulnscan-backend/sitemonitor"
	"vulnscan-backend/tagging"
	"vulnscan-backend/task"
	tmplAPI "vulnscan-backend/template/api"
	engine "vulnscan-backend/template/engine"
	"vulnscan-backend/vuln"

	"code.yt-security.com/public/core/v2/cache"
	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"code.yt-security.com/public/core/v2/product"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handlers struct {
	Config  *boot.Config
	Web     *web.Web
	DB      *db.DB
	Cache   cache.Cache
	Product *product.SystemProduct
	IAM     *iamsdk.Client

	Asset       *asset.Asset
	Task        *task.Task
	Vuln        *vuln.Vuln
	Cluster     *cluster.Cluster
	Tagging     *tagging.Tagging
	Organize    *organize.Organize
	AssetMgr    *assetmgr.AssetMgr
	SiteMonitor *sitemonitor.Monitor
	Circular    *circular.Circular
	Incident    *incident.Incident

	embeddedAgent *monitoragent.EmbeddedAgent
	fedClient     *fedClient.Client
	wsHub         *ws.Hub
	sched         *scheduler.Scheduler
	cronRunner    *schedule.CronRunner
	Settings      *setting.Handler
}

func (h *Handlers) RouteLoad() {
	h.autoMigrate()
	h.initSettings()

	engine := h.Web.GetRawWeb()
	engine.Use(web.MiddlewareRequestResponse())

	apiGroup := engine.Group("/api")

	iamAuthGroup := apiGroup.Group("/",
		h.IAM.Middleware().Authentication(),
		h.IAM.Middleware().Authorization(),
	)

	var ssoOpts *iamsdk.SSORoutesOptions
	if h.Config.SSO.CallbackURI != "" {
		ssoOpts = &iamsdk.SSORoutesOptions{
			CallbackURI:           h.Config.SSO.CallbackURI,
			SuccessRedirect:       h.Config.SSO.SuccessRedirect,
			CookieSecret:          []byte(h.Config.SSO.CookieSecret),
			TokenRelayCallbackURI: h.Config.SSO.TokenRelayCallbackURI,
		}
	}
	h.IAM.RegisterDefaultRoutes(engine, iamAuthGroup, iamsdk.DefaultRoutesOptions{
		SSO: ssoOpts,
		Audit: &iamsdk.AuditMiddlewareOptions{
			Domain:  h.Product.GetCode(),
			Enabled: true,
		},
	})

	var backends []authorize.BackendItem
	backends = append(backends, h.Asset.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Task.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Vuln.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Cluster.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Tagging.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Organize.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.AssetMgr.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.SiteMonitor.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Circular.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Incident.RoutesWithGroup(iamAuthGroup)...)

	settingRoutes := setting.NewSettingRoutes(h.Settings)
	backends = append(backends, settingRoutes.RoutesWithGroup(iamAuthGroup)...)

	h.initDashboardAPI(iamAuthGroup, &backends)
	h.initNotifyAPI(iamAuthGroup, &backends)
	h.initCyberspaceAPI(iamAuthGroup, &backends)
	h.initKnowledgeAPIs(iamAuthGroup, &backends)
	h.initTemplateAPI(iamAuthGroup, &backends)
	h.initScheduler(iamAuthGroup, &backends)
	h.initCronScheduler(iamAuthGroup, &backends)
	h.initASMAPI(iamAuthGroup, &backends)
	h.initIntelAPI(iamAuthGroup, &backends)
	h.initComplianceAPI(iamAuthGroup, &backends)
	h.initWebSocket(apiGroup)

	h.initUnifiedNodes(iamAuthGroup)
	h.initFederationManageAPI(iamAuthGroup)

	h.syncBackends(backends)
	h.initFederation()

	healthHandler := health.NewHandler(h.DB)
	healthHandler.RegisterRoutes(engine)

	h.SiteMonitor.RegisterAgentAPI(engine, h.Config.IAM.PathPrefix)

	sitemonitor.InitDefaultRuleData(h.DB)

	h.embeddedAgent = monitoragent.NewEmbeddedAgent(h.DB, "")
	h.embeddedAgent.Start()

	h.SiteMonitor.StartScheduler()

	frontend.SetupSPA(engine, web.MiddlewareNotFound())
}

func (h *Handlers) initScheduler(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Scheduler] 获取数据库会话失败", "error", err)
		return
	}

	h.sched = scheduler.New(session, 10)
	h.sched.Start(context.Background())

	scanAPI := scheduler.NewAPI(session, h.sched)
	*backends = append(*backends, scanAPI.RoutesWithGroup(authGroup)...)

	reportAPI := scheduler.NewReportAPI(session)
	reportAPI.RegisterRoutes(authGroup)

	pipelineAPI := scheduler.NewPipelineAPI(session)
	pipelineAPI.RegisterRoutes(authGroup)

	slog.Info("[+] Scheduler + Report + Pipeline API 已注册")
}

func (h *Handlers) initUnifiedNodes(authGroup *gin.RouterGroup) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		return
	}
	cluster.RegisterUnifiedNodeRoutes(authGroup, session)
}

func (h *Handlers) initWebSocket(apiGroup *gin.RouterGroup) {
	h.wsHub = h.initWSHub()
	wsHandler := ws.NewWSHandler(h.wsHub)
	wsHandler.RegisterRoutes(apiGroup)
	slog.Info("[+] WebSocket Hub 已启动")
}

func (h *Handlers) initWSHub() *ws.Hub {
	svc := cluster.NewServiceClusterForWS(h.DB)
	hub := ws.NewHub(svc)
	go hub.Run()
	return hub
}

func (h *Handlers) initSettings() {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Setting] 获取数据库会话失败", "error", err)
		return
	}
	h.Settings = setting.NewHandler(session)
	h.Settings.SeedDefaults()
	slog.Info("[+] 系统设置模块已初始化")
}

func (h *Handlers) autoMigrate() {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[!] 获取数据库会话失败", "error", err)
		return
	}

	tables := []interface{}{
		&model.Asset{},
		&model.AssetGroup{},
		&model.AssetRelation{},
		&model.AssetRiskHistory{},
		&model.ScanTask{},
		&model.Vulnerability{},
		&model.ScanFinding{},
		&model.ScanTemplate{},
		&model.WorkerNode{},
		&model.ServiceFingerprint{},
		&model.WebFingerprint{},
		&model.PortServiceMap{},
		&model.Dictionary{},
		&model.DictionaryEntry{},
		&model.ScanRule{},
		&model.PocTemplate{},
		&model.FederationSyncState{},
		&model.FederationReportBuffer{},
		&model.ScanLog{},
		&model.ScanSchedule{},
		&model.VulnStatusHistory{},
		&model.Notification{},
		// 资产增强模型
		&model.Tag{},
		&model.AssetTag{},
		&model.AssetChangeLog{},
		&model.Organize{},
		&model.ConstructionOrg{},
		&model.AssetLifecycle{},
		&model.AssetCompliance{},
		&model.AssetResponsible{},
		&model.AssetRiskScore{},
		&model.Alert{},
		&model.AssetVerify{},
		&model.ComplianceTemplate{},
		&model.ComplianceTemplateItem{},
		&model.ComplianceCheckResult{},
		&model.IntegrationSource{},
		&model.IntegrationEvent{},
		&model.Workflow{},
		&model.WorkflowExecution{},
		&model.SystemSetting{},
		// 站点监控
		&model.MonitorTask{},
		&model.MonitorDefaultConfig{},
		&model.MonitorExecution{},
		&model.MonitorAlert{},
		&model.MonitorAlertConfig{},
		&model.MonitorDispositionLog{},
		&model.MonitorAgent{},
		&model.MonitorBaseline{},
		&model.MonitorFingerprintWindow{},
		&model.MonitorWordLibrary{},
		&model.MonitorWordCategory{},
		&model.MonitorWordEntry{},
		&model.MonitorFileLibrary{},
		&model.MonitorFileEntry{},
		&model.MonitorResultSensitiveWord{},
		&model.MonitorResultSensitiveWordMatch{},
		&model.MonitorResultSensitiveFile{},
		&model.MonitorResultSensitiveFileFinding{},
		&model.MonitorRuleData{},
		&model.MonitorPerfBaseline{},
		// 威胁情报订阅 + IOC
		&model.IntelSubscription{},
		&model.IOCIndicator{},
		// ASM 攻击面管理
		&model.ASMProject{},
		&model.ASMSeed{},
		&model.ASMDiscoveredAsset{},
		&model.ASMChange{},
		&model.ASMAlertRule{},
	}

	if migrateErr := session.AutoMigrate(tables...); migrateErr != nil {
		slog.Error("[!] 数据库迁移失败", "error", migrateErr)
	} else {
		slog.Info("[+] 数据库迁移完成", "tables", len(tables))
	}

	if err := migration.RunAll(session); err != nil {
		slog.Error("[!] 数据迁移脚本执行失败", "error", err)
	}

	reconCategories := []string{
		"host_alive", "port_open", "udp_port", "service",
		"web_page", "dns_record", "subdomain", "cert_info",
		"favicon", "tech", "api", "waf", "js_info", "crawler",
	}
	result := session.Where("category IN ?", reconCategories).Delete(&model.Vulnerability{})
	if result.RowsAffected > 0 {
		slog.Info("[+] 已清理信息收集类误入漏洞表的记录", "count", result.RowsAffected)
	}
}

func (h *Handlers) syncBackends(backends []authorize.BackendItem) {
	if len(backends) == 0 || h.Config.IAM.ClientID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.IAM.Authorize.SyncBackends(ctx, h.Config.IAM.ClientID, backends); err != nil {
		slog.Error("sync backends to IAM failed", "err", err)
		return
	}
	slog.Info("[+] 后端接口已同步到 IAM", "count", len(backends))
}

func (h *Handlers) initFederationManageAPI(authGroup *gin.RouterGroup) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		return
	}
	server.RegisterManageRoutes(authGroup, session)
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
		ginEngine := h.Web.GetRawWeb()
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

func (h *Handlers) initNotifyAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Notify] 获取数据库会话失败", "error", err)
		return
	}
	handler := notify.NewHandler(session)
	routes := notify.NewNotifyRoutes(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] Notify API 已注册")
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

func (h *Handlers) initDashboardAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Dashboard] 获取数据库会话失败", "error", err)
		return
	}
	dashHandler := dashboard.NewHandler(session)
	dashRoutes := dashboard.NewDashboard(dashHandler)
	*backends = append(*backends, dashRoutes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] Dashboard API 已注册")
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

func (h *Handlers) seedBuiltinTemplates(session *gorm.DB) {
	builtins := engine.BuiltinTemplates()
	for _, bt := range builtins {
		var count int64
		session.Model(&model.ScanTemplate{}).Where("code = ?", bt.ID).Count(&count)
		if count > 0 {
			continue
		}
		content, _ := json.Marshal(bt)
		item := model.ScanTemplate{
			ID:          qulid.GenerateID(),
			Name:        bt.Name,
			Code:        bt.ID,
			Category:    "builtin",
			Description: bt.Description,
			Tags:        model.StringArray(bt.Tags),
			Content:     string(content),
			Version:     bt.Version,
			Builtin:     true,
			Enabled:     true,
			AuthorID:    "system",
		}
		session.Create(&item)
	}
}

func (h *Handlers) initCronScheduler(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Cron] 获取数据库会话失败", "error", err)
		return
	}

	schedHandler := schedule.NewHandler(session)
	schedRoutes := schedule.NewSchedule(schedHandler)
	*backends = append(*backends, schedRoutes.RoutesWithGroup(authGroup)...)

	h.cronRunner = schedule.NewCronRunner(session, h.sched)
	h.cronRunner.Start(context.Background())

	slog.Info("[+] 定时调度 API + Cron Runner 已注册")
}

func (h *Handlers) initKnowledgeAPIs(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	session, err := h.DB.GetDBSession()
	if err != nil {
		slog.Error("[Knowledge] 获取数据库会话失败", "error", err)
		return
	}

	pocStore := nuclei.NewPocStore(session)
	pocSvc := poc.NewServicePoc(h.DB, pocStore)
	pocHandler := poc.NewHandlerPoc(pocSvc)
	pocRoutes := poc.NewPoc(pocHandler)
	*backends = append(*backends, pocRoutes.RoutesWithGroup(authGroup)...)

	fpSvc := kfp.NewServiceFingerprint(h.DB)
	fpHandler := kfp.NewHandlerFingerprint(fpSvc)
	webFpSvc := kfp.NewServiceWebFingerprint(h.DB)
	webFpHandler := kfp.NewHandlerWebFingerprint(webFpSvc)
	fpRoutes := kfp.NewFingerprintFull(fpHandler, webFpHandler)
	*backends = append(*backends, fpRoutes.RoutesWithGroup(authGroup)...)

	dictSvc := kdict.NewServiceDict(h.DB)
	dictHandler := kdict.NewHandlerDict(dictSvc)
	dictRoutes := kdict.NewDict(dictHandler)
	*backends = append(*backends, dictRoutes.RoutesWithGroup(authGroup)...)

	slog.Info("[+] POC + Fingerprint + Dict 知识库 API 已注册")
}

func (h *Handlers) initComplianceAPI(authGroup *gin.RouterGroup, backends *[]authorize.BackendItem) {
	handler := compliance.NewHandler()
	routes := compliance.NewCompliance(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] 合规检查 API 已注册")
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

	handler := asm.NewHandler(h.DB, collectors...)
	routes := asm.NewASM(handler)
	*backends = append(*backends, routes.RoutesWithGroup(authGroup)...)
	slog.Info("[+] ASM 攻击面管理 API 已注册", "cyberspace_providers", len(cyberConfigs))
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

func (h *Handlers) Shutdown() {
	if h.cronRunner != nil {
		h.cronRunner.Stop()
	}
	if h.sched != nil {
		h.sched.Stop()
	}
	if h.fedClient != nil {
		h.fedClient.Stop()
	}
	if h.wsHub != nil {
		h.wsHub.Stop()
	}
	if h.embeddedAgent != nil {
		h.embeddedAgent.Stop()
	}
	h.SiteMonitor.StopScheduler()
	if nats := h.SiteMonitor.GetNatsService(); nats != nil {
		nats.Close()
	}
	h.IAM.Close()
}
