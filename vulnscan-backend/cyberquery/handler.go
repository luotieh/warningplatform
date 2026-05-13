package cyberquery

import (
	"log/slog"
	"strconv"

	"code.yt-security.com/public/core/v2/web"
	"code.yt-security.com/public/sdk/authorize"
	"github.com/gin-gonic/gin"

	"vulnscan-backend/scan/module/cyberspace"
)

type Handler struct {
	providers map[string]cyberspace.Provider
	configs   map[string]cyberspace.ProviderConfig
}

func NewHandler(configs map[string]cyberspace.ProviderConfig) *Handler {
	h := &Handler{
		configs:   configs,
		providers: make(map[string]cyberspace.Provider),
	}

	if cfg, ok := configs["shodan"]; ok && cfg.Enabled {
		h.providers["shodan"] = cyberspace.NewShodan(cfg)
	}
	if cfg, ok := configs["fofa"]; ok && cfg.Enabled {
		h.providers["fofa"] = cyberspace.NewFOFA(cfg)
	}
	if cfg, ok := configs["zoomeye"]; ok && cfg.Enabled {
		h.providers["zoomeye"] = cyberspace.NewZoomEye(cfg)
	}
	if cfg, ok := configs["censys"]; ok && cfg.Enabled {
		h.providers["censys"] = cyberspace.NewCensys(cfg)
	}

	return h
}

func (h *Handler) Search(c *gin.Context) {
	query := c.Query("q")
	providerName := c.Query("provider")
	maxStr := c.DefaultQuery("max", "100")
	maxResults, _ := strconv.Atoi(maxStr)
	if maxResults <= 0 {
		maxResults = 100
	}

	if query == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var assets []*cyberspace.CyberAsset
	if providerName != "" {
		p, ok := h.providers[providerName]
		if !ok {
			web.Err(c, web.ParamsMissingRequired).Send()
			return
		}
		var err error
		assets, err = p.Search(query, maxResults)
		if err != nil {
			slog.Error("cyberspace search failed", "provider", providerName, "error", err)
			web.Fail(c).Err(err).Send()
			return
		}
	} else {
		for name, p := range h.providers {
			results, err := p.Search(query, maxResults/len(h.providers))
			if err != nil {
				slog.Warn("cyberspace search partial fail", "provider", name, "error", err)
				continue
			}
			assets = append(assets, results...)
		}
	}

	web.OK(c).List(int64(len(assets)), assets).Send()
}

func (h *Handler) HostLookup(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	var assets []*cyberspace.CyberAsset
	for name, p := range h.providers {
		results, err := p.HostLookup(ip)
		if err != nil {
			slog.Warn("cyberspace host lookup partial fail", "provider", name, "error", err)
			continue
		}
		assets = append(assets, results...)
	}

	web.OK(c).List(int64(len(assets)), assets).Send()
}

func (h *Handler) ListProviders(c *gin.Context) {
	type providerInfo struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}

	var list []providerInfo
	for name, cfg := range h.configs {
		list = append(list, providerInfo{
			Name:    name,
			Enabled: cfg.Enabled && cfg.APIKey != "",
		})
	}

	web.OK(c).Data(list).Send()
}

type CyberQuery struct {
	handler *Handler
}

func NewCyberQuery(handler *Handler) *CyberQuery {
	return &CyberQuery{handler: handler}
}

func (m *CyberQuery) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/cyberquery"), []authorize.Route{
		{
			Name: "网络空间搜索", Enabled: true,
			Children: []authorize.Route{
				{Name: "搜索查询", Path: "search", Method: "GET", Handler: m.handler.Search, Enabled: true},
				{Name: "主机查询", Path: "host", Method: "GET", Handler: m.handler.HostLookup, Enabled: true},
				{Name: "平台列表", Path: "providers", Method: "GET", Handler: m.handler.ListProviders, Enabled: true},
			},
		},
	})
}
