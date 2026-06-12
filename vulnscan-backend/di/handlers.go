package di

import (
	"context"
	"io"
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
	"vulnscan-backend/dispatch"
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

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/access/proxy"
	"code.yt-security.com/public/access/storage"
	"code.yt-security.com/public/core/cache"
	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/product"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Handlers struct {
	Config  *boot.Config
	Web     *web.Engine
	DB      *db.DB
	Cache   cache.Cache
	Product *product.Product
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
	Dispatch    *dispatch.Dispatch
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

	engine := h.Web
	engine.Use(web.MiddlewareRequestResponse())

	apiGroup := engine.Group("/api")

	h.IAM.RegisterProxyRoutes(apiGroup, proxy.Options{
		MountPrefix: "iam",
		ClientID:    h.Config.IAM.ClientID,
		PublicAuth: &proxy.PublicAuthOptions{
			SiteName:  h.Product.GetName(),
			Copyright: h.Product.GetName(),
		},
	})

	apiAuthenticated := apiGroup.Group("/", h.IAM.Middleware().Authentication())
	h.registerPrivilegedFrontendSync(apiAuthenticated)

	apiAuthorized := apiAuthenticated.Group("", h.IAMAuthorization())

	var backends []authorize.BackendItem
	backends = append(backends, authorize.BackendItem{
		Method: "POST",
		Path:   "/api/system/iam/sync-frontends",
		Name:   "同步前端菜单到IAM",
	})
	backends = append(backends,
		authorize.BackendItem{Method: "GET", Path: "/api/iam/todos", Name: "待办事项列表", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/iam/todos/stats", Name: "待办事项统计", Enabled: true},
		authorize.BackendItem{Method: "POST", Path: "/api/iam/todos", Name: "创建待办事项", Enabled: true},
		authorize.BackendItem{Method: "PUT", Path: "/api/iam/todos/:id", Name: "更新待办事项", Enabled: true},
		authorize.BackendItem{Method: "PUT", Path: "/api/iam/todos/:id/status", Name: "更新待办状态", Enabled: true},
		authorize.BackendItem{Method: "DELETE", Path: "/api/iam/todos/:id", Name: "删除待办事项", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/notify/list", Name: "通知列表", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/notify/unread-count", Name: "未读通知数", Enabled: true},
		authorize.BackendItem{Method: "POST", Path: "/api/notify/:id/read", Name: "标记通知已读", Enabled: true},
		authorize.BackendItem{Method: "POST", Path: "/api/notify/read-all", Name: "全部标记已读", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/nodes", Name: "节点列表", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/sitemonitor/executions/export", Name: "导出监测记录", Enabled: true},
		authorize.BackendItem{Method: "GET", Path: "/api/sitemonitor/reports", Name: "监测报告列表", Enabled: true},
	)
	backends = append(backends, h.Asset.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Task.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Vuln.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Cluster.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Tagging.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Organize.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.AssetMgr.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.SiteMonitor.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Circular.RoutesWithGroup(apiAuthorized)...)
	backends = append(backends, h.Dispatch.RoutesWithGroup(apiAuthorized)...)
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

	backends = append(backends, h.initUnifiedNodes(apiAuthorized)...)
	backends = append(backends, h.initFederationManageAPI(apiAuthorized)...)

	h.syncBackends(backends)
	h.initFederation()

	healthHandler := health.NewHandler(h.DB)
	healthHandler.RegisterRoutes(engine.Engine)

	if metricsRouteEnabled() {
		engine.GET("/metrics", gin.WrapH(promhttp.Handler()))
		slog.Info("[+] Prometheus /metrics 已启用（环境变量 VULNSCAN_METRICS_ENABLED）")
	}

	h.initNodeAPI(engine.Engine)

	sitemon.InitDefaultRuleData(h.DB)

	h.embeddedAgent = monitoragent.NewEmbeddedAgent(h.DB, "")
	if nats := h.SiteMonitor.GetNatsService(); nats != nil {
		h.embeddedAgent.SetScreenshotStore(nats.StoreEvidenceScreenshot)
	}

	h.injectCrawlScreenshotUploader()
	h.injectAnnotatedScreenshotUploader()

	h.embeddedAgent.Start()

	h.SiteMonitor.StartScheduler()

	frontend.SetupSPA(engine.Engine, web.MiddlewareNotFound())
}

func (h *Handlers) injectCrawlScreenshotUploader() {
	if h.IAM == nil {
		return
	}
	iamBase := strings.TrimRight(h.Config.IAM.BaseURL, "/")
	storageBaseURL := iamBase + h.Config.IAM.PathPrefix + "/storage/file"

	uploader := func(ctx context.Context, jpegData []byte, name string) (string, error) {
		req := storage.FileUploadRequest{
			PolicyCode:  "default",
			FileName:    "crawl-" + name + ".jpg",
			ContentType: "image/jpeg",
			Data:        jpegData,
			BizType:     "crawl_screenshot",
			App:         "vulnscan",
		}
		if uid := sitemon.CreatorIDFromContext(ctx); uid != "" {
			req.UserID = uid
		}
		file, err := h.IAM.Storage.UploadSimpleAsService(ctx, req)
		if err != nil {
			return "", err
		}
		return file.ID, nil
	}
	h.SiteMonitor.SetCrawlScreenshotUploader(uploader, storageBaseURL)
	slog.Info("[+] 爬虫截图上传能力已注入（IAM Storage）")
}

func (h *Handlers) injectAnnotatedScreenshotUploader() {
	if h.IAM == nil || h.embeddedAgent == nil {
		return
	}
	iamBase := strings.TrimRight(h.Config.IAM.BaseURL, "/")
	storageBaseURL := iamBase + h.Config.IAM.PathPrefix + "/storage/file"

	uploader := func(ctx context.Context, jpegData []byte, name string) (string, error) {
		req := storage.FileUploadRequest{
			PolicyCode:  "default",
			FileName:    name + ".jpg",
			ContentType: "image/jpeg",
			Data:        jpegData,
			BizType:     "tamper_screenshot",
			App:         "vulnscan",
		}
		file, err := h.IAM.Storage.UploadSimpleAsService(ctx, req)
		if err != nil {
			return "", err
		}
		return file.ID, nil
	}
	deleter := func(ctx context.Context, fileID string) error {
		return h.IAM.Storage.DeleteFileAsService(ctx, fileID)
	}
	h.embeddedAgent.SetAnnotatedUploader(uploader, deleter, storageBaseURL)
	slog.Info("[+] 标注截图上传能力已注入（IAM Storage）")

	h.SiteMonitor.SetFileDownloader(func(ctx context.Context, fileID string) (io.ReadCloser, string, error) {
		result, err := h.IAM.Storage.DownloadFileAsService(ctx, fileID)
		if err != nil {
			return nil, "", err
		}
		return result.Content, result.ContentType, nil
	})
	slog.Info("[+] IAM Storage 文件下载能力已注入")
}

func (h *Handlers) syncBackends(backends []authorize.BackendItem) {
	if len(backends) == 0 || h.Config.IAM.ClientID == "" {
		return
	}

	leafCount := 0
	countLeaves(backends, &leafCount)
	slog.Info("[sync-backends] 准备同步", "top_level", len(backends), "leaf_endpoints", leafCount)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.IAM.SyncBackends(ctx, backends); err != nil {
		slog.Error("sync backends to IAM failed", "err", err)
		return
	}
	slog.Info("[+] 后端接口已同步到 IAM", "count", len(backends), "leaf_endpoints", leafCount)
}

func countLeaves(items []authorize.BackendItem, count *int) {
	for i := range items {
		if len(items[i].Children) > 0 {
			countLeaves(items[i].Children, count)
		} else if items[i].Method != "" {
			*count++
		}
	}
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
