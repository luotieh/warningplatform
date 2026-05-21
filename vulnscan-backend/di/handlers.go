package di

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"vulnscan-backend/asset"
	"vulnscan-backend/assetmgr"
	"vulnscan-backend/boot"
	"vulnscan-backend/circular"
	"vulnscan-backend/cluster"
	"vulnscan-backend/cluster/ws"
	"vulnscan-backend/compliance"
	"vulnscan-backend/dashboard"
	"vulnscan-backend/exclusion"
	fedClient "vulnscan-backend/federation/client"
	"vulnscan-backend/formdesign"
	"vulnscan-backend/fprule"
	"vulnscan-backend/frontend"
	"vulnscan-backend/health"
	"vulnscan-backend/incident"
	"vulnscan-backend/monitoragent"
	"vulnscan-backend/notify"
	"vulnscan-backend/organize"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/report"
	"vulnscan-backend/scanrunner"
	"vulnscan-backend/schedule"
	"vulnscan-backend/setting"
	sitemon "vulnscan-backend/sitemonitor"
	"vulnscan-backend/systemdict"
	"vulnscan-backend/tagging"
	"vulnscan-backend/task"
	"vulnscan-backend/vuln"

	"code.yt-security.com/public/core/v2/cache"
	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/product"
	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	SiteMonitor *sitemon.Monitor
	Circular    *circular.Circular
	Incident    *incident.Incident
	Dashboard   *dashboard.Dashboard
	Notify      *notify.NotifyRoutes
	Compliance  *compliance.Compliance
	Report      *report.Report
	Exclusion   *exclusion.Exclusion
	FPRule      *fprule.FPRule

	embeddedAgent *monitoragent.EmbeddedAgent
	fedClient     *fedClient.Client
	wsHub         *ws.Hub
	sched         *scanrunner.Scheduler
	cronRunner    *schedule.CronRunner
	Settings      *setting.Handler
	payloadLoader *payload.Loader
	Knowledge     *scanrunner.KnowledgeRegistry
}

func (h *Handlers) RouteLoad() {
	h.autoMigrate()
	h.initSettings()
	h.wireIncidentReportExporter()

	engine := h.Web.GetRawWeb()
	engine.Use(web.MiddlewareRequestResponse())

	apiGroup := engine.Group("/api")

	// 仅认证：IAM SDK 的 /me/*、/auth/refresh 等用用户 token 代理 IAM（Authenticated 端点），
	// 不应再走 SyncBackends 的接口级 RBAC，否则非特权用户访问 /me/profile 会 403 并触发前端降级。
	apiAuthenticated := apiGroup.Group("/", h.IAM.Middleware().Authentication())

	var ssoOpts *iamsdk.SSORoutesOptions
	if h.Config.SSO.CallbackURI != "" {
		ssoOpts = &iamsdk.SSORoutesOptions{
			CallbackURI:           h.Config.SSO.CallbackURI,
			SuccessRedirect:       h.Config.SSO.SuccessRedirect,
			CookieSecret:          []byte(h.Config.SSO.CookieSecret),
			TokenRelayCallbackURI: h.Config.SSO.TokenRelayCallbackURI,
		}
	}
	h.registerPrivilegedFrontendSync(apiAuthenticated)

	h.IAM.RegisterDefaultRoutes(engine, apiAuthenticated, iamsdk.DefaultRoutesOptions{
		SSO: ssoOpts,
		Audit: &iamsdk.AuditMiddlewareOptions{
			Domain:  h.Product.GetCode(),
			Enabled: false,
		},
		PublicAuth: &iamsdk.PublicAuthProxyOptions{
			SiteName:  h.Product.GetName(),
			Copyright: h.Product.GetName(),
		},
	})

	apiAuthorized := apiAuthenticated.Group("", h.ModuleAuthorization())

	var backends []authorize.BackendItem
	backends = append(backends, h.Asset.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Task.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Vuln.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Cluster.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Tagging.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Organize.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.AssetMgr.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.SiteMonitor.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Circular.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Incident.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Dashboard.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Notify.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Compliance.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Report.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Exclusion.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.FPRule.RoutesWithGroup(apiAuthorized)...)

	settingRoutes := setting.NewSettingRoutes(h.Settings)
	backends = append(backends, settingRoutes.RoutesWithGroup(apiAuthorized)...)
	systemDictSvc := systemdict.NewServiceSystemDict(h.DB)
	systemDictHandler := systemdict.NewHandler(systemDictSvc)
	systemDictHandler.SeedDefaults()
	systemDictRoutes := systemdict.NewRoutes(systemDictHandler)
	backends = append(backends, systemDictRoutes.RoutesWithGroup(apiAuthorized)...)
	formSvc := formdesign.NewServiceFormDesign(h.DB)
	formHandler := formdesign.NewHandler(formSvc)
	formRoutes := formdesign.NewRoutes(formHandler)
	backends = append(backends, formRoutes.RoutesWithGroup(apiAuthorized)...)

	h.initCyberspaceAPI(apiAuthorized, &backends)
	h.initKnowledgeAPIs(apiAuthorized, &backends)
	h.initTemplateAPI(apiAuthorized, &backends)
	h.initScheduler(apiAuthorized, &backends)
	h.initCronScheduler(apiAuthorized, &backends)
	h.initASMAPI(apiAuthorized, &backends)
	h.initIntelAPI(apiAuthorized, &backends)
	h.initWebSocket(apiGroup)

	h.initUnifiedNodes(apiAuthorized)
	h.initFederationManageAPI(apiAuthorized)

	h.syncBackends(backends)
	h.initFederation()

	healthHandler := health.NewHandler(h.DB)
	healthHandler.RegisterRoutes(engine)

	if metricsRouteEnabled() {
		engine.GET("/metrics", gin.WrapH(promhttp.Handler()))
		slog.Info("[+] Prometheus /metrics 已启用（环境变量 VULNSCAN_METRICS_ENABLED）")
	}

	h.initNodeAPI(engine)

	sitemon.InitDefaultRuleData(h.DB)

	h.embeddedAgent = monitoragent.NewEmbeddedAgent(h.DB, "")
	h.embeddedAgent.Start()

	h.SiteMonitor.StartScheduler()

	frontend.SetupSPA(engine, web.MiddlewareNotFound())
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

func metricsRouteEnabled() bool {
	s := strings.ToLower(strings.TrimSpace(os.Getenv("VULNSCAN_METRICS_ENABLED")))
	return s == "true" || s == "1" || s == "yes"
}
