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
			Enabled: false,
		},
		PublicAuth: &iamsdk.PublicAuthProxyOptions{
			SiteName:  h.Product.GetName(),
			Copyright: h.Product.GetName(),
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
	backends = append(backends, h.Dashboard.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Notify.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Compliance.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Report.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.Exclusion.RoutesWithGroup(iamAuthGroup)...)
	backends = append(backends, h.FPRule.RoutesWithGroup(iamAuthGroup)...)

	settingRoutes := setting.NewSettingRoutes(h.Settings)
	backends = append(backends, settingRoutes.RoutesWithGroup(iamAuthGroup)...)
	systemDictSvc := systemdict.NewServiceSystemDict(h.DB)
	systemDictHandler := systemdict.NewHandler(systemDictSvc)
	systemDictHandler.SeedDefaults()
	systemDictRoutes := systemdict.NewRoutes(systemDictHandler)
	backends = append(backends, systemDictRoutes.RoutesWithGroup(iamAuthGroup)...)
	formSvc := formdesign.NewServiceFormDesign(h.DB)
	formHandler := formdesign.NewHandler(formSvc)
	formRoutes := formdesign.NewRoutes(formHandler)
	backends = append(backends, formRoutes.RoutesWithGroup(iamAuthGroup)...)

	h.initCyberspaceAPI(iamAuthGroup, &backends)
	h.initKnowledgeAPIs(iamAuthGroup, &backends)
	h.initTemplateAPI(iamAuthGroup, &backends)
	h.initScheduler(iamAuthGroup, &backends)
	h.initCronScheduler(iamAuthGroup, &backends)
	h.initASMAPI(iamAuthGroup, &backends)
	h.initIntelAPI(iamAuthGroup, &backends)
	h.initWebSocket(apiGroup)

	h.initUnifiedNodes(iamAuthGroup)
	h.initFederationManageAPI(iamAuthGroup)

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
