package clusterconn

import (
	"fmt"
	"os"
	"strings"

	"vulnscan-backend/boot"
)

// 部署拓扑：控制面均为节点主动连接主控（出站拉取），区别仅在于节点能否访问 MasterURL。
const (
	TopologyMasterPublicNodePrivate = "master_public_node_private" // 主控公网，节点内网
	TopologyMasterPrivateNodePublic = "master_private_node_public" // 主控内网，节点公网
)

// Options 集群连通性配置（签发凭据与入网指引）。
type Options struct {
	PublicMasterURL   string // 节点从外网访问主控的 URL（含 IAM path_prefix），如 https://scan.example.com/api
	InternalMasterURL string // 主控内网自引用 URL（可选，管理端展示）
	PathPrefix        string // IAM path_prefix，默认 /api
}

func OptionsFromEnv() Options {
	return Options{
		PublicMasterURL:   strings.TrimSpace(os.Getenv("VULNSCAN_CLUSTER_PUBLIC_MASTER_URL")),
		InternalMasterURL: strings.TrimSpace(os.Getenv("VULNSCAN_CLUSTER_INTERNAL_MASTER_URL")),
		PathPrefix:        strings.TrimSpace(os.Getenv("VULNSCAN_IAM_PATH_PREFIX")),
	}
}

func OptionsFromConfig(cfg *boot.Config) Options {
	o := OptionsFromEnv()
	if cfg == nil {
		if o.PathPrefix == "" {
			o.PathPrefix = "/api"
		}
		return o
	}
	if cfg.Cluster.PublicMasterURL != "" {
		o.PublicMasterURL = strings.TrimRight(strings.TrimSpace(cfg.Cluster.PublicMasterURL), "/")
	}
	if cfg.Cluster.InternalMasterURL != "" {
		o.InternalMasterURL = strings.TrimRight(strings.TrimSpace(cfg.Cluster.InternalMasterURL), "/")
	}
	if cfg.IAM.PathPrefix != "" {
		o.PathPrefix = strings.TrimSpace(cfg.IAM.PathPrefix)
	} else if o.PathPrefix == "" {
		o.PathPrefix = "/api"
	}
	return o
}

// ModeInfo 一种部署模式的说明与建议 MasterURL。
type ModeInfo struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Summary           string   `json:"summary"`
	SuggestedURL      string   `json:"suggested_master_url"`
	NodeRequirement   string   `json:"node_requirement"`
	MasterRequirement string   `json:"master_requirement"`
	FirewallNotes     []string `json:"firewall_notes"`
	Supported         bool     `json:"supported"`
}

// ConnectivityModesResponse GET /cluster/connectivity-modes
type ConnectivityModesResponse struct {
	Modes             []ModeInfo `json:"modes"`
	DefaultMode       string     `json:"default_mode"`
	PublicMasterURL   string     `json:"public_master_url"`
	InternalMasterURL string     `json:"internal_master_url"`
	ControlPlane      string     `json:"control_plane"` // 固定 pull
}

func BuildConnectivityModes(opts Options) *ConnectivityModesResponse {
	pub := strings.TrimRight(strings.TrimSpace(opts.PublicMasterURL), "/")
	internal := strings.TrimRight(strings.TrimSpace(opts.InternalMasterURL), "/")

	masterPublic := ModeInfo{
		ID:                TopologyMasterPublicNodePrivate,
		Title:             "主控公网 · 节点内网",
		Summary:           "扫描节点位于内网或 NAT 后，通过出站 HTTPS 连接公网主控；无需节点开放入站端口。",
		SuggestedURL:      pub,
		NodeRequirement:   "节点需能访问主控公网地址（出站 443/80）",
		MasterRequirement: "主控暴露 node-api / WebSocket 入口（公网 IP、负载均衡或反向代理）",
		FirewallNotes: []string{
			"节点侧：放行访问主控的出站 HTTPS",
			"主控侧：放行入站 HTTPS（及 WSS）到 API 网关",
			"凭据中的 master_url 填写节点可达的公网地址（含 /api 等前缀）",
		},
		Supported: pub != "",
	}

	masterPrivate := ModeInfo{
		ID:                TopologyMasterPrivateNodePublic,
		Title:             "主控内网 · 节点公网",
		Summary:           "主控仅在内网，公网扫描节点通过 DMZ/边界反向代理访问主控对外入口；仍为节点主动拉取任务。",
		SuggestedURL:      pub,
		NodeRequirement:   "公网节点需能访问「主控对外入口」URL（与内网主控通过网关打通）",
		MasterRequirement: "在内网部署主控，并在边界配置反向代理/端口映射，将 /node-api 暴露给外网节点",
		FirewallNotes: []string{
			"配置 cluster.public_master_url 为外网节点使用的入口（如 https://gateway.corp.com/api）",
			"边界设备将请求转发至内网主控，禁止依赖主控主动连接节点",
			"若无公网入口，需在边界部署 HTTPS 反代将 /node-api 转发至内网主控",
		},
		Supported: pub != "",
	}

	defaultMode := TopologyMasterPublicNodePrivate
	if pub == "" && internal != "" {
		defaultMode = TopologyMasterPrivateNodePublic
	}

	return &ConnectivityModesResponse{
		Modes:             []ModeInfo{masterPublic, masterPrivate},
		DefaultMode:       defaultMode,
		PublicMasterURL:   pub,
		InternalMasterURL: internal,
		ControlPlane:      "pull",
	}
}

// ResolveMasterURL 根据拓扑与配置解析签发凭据用的 master_url。
func ResolveMasterURL(topology, requestURL string, opts Options) (string, error) {
	if u := strings.TrimRight(strings.TrimSpace(requestURL), "/"); u != "" {
		return u, nil
	}
	pub := strings.TrimRight(strings.TrimSpace(opts.PublicMasterURL), "/")
	switch strings.TrimSpace(topology) {
	case "", TopologyMasterPublicNodePrivate, TopologyMasterPrivateNodePublic:
		if pub == "" {
			return "", fmt.Errorf("请填写 master_url，或在配置中设置 cluster.public_master_url（节点访问主控的对外地址）")
		}
		return pub, nil
	default:
		return "", fmt.Errorf("未知部署拓扑: %s", topology)
	}
}

// AgentConnectivityHint 连接失败时的排查提示。
func AgentConnectivityHint(topology string) string {
	switch strings.TrimSpace(topology) {
	case TopologyMasterPrivateNodePublic:
		return "当前为「主控内网·节点公网」：请确认 master_url 为边界反代/网关地址，且已转发 /node-api（无需 VPN）"
	case TopologyMasterPublicNodePrivate:
		return "当前为「主控公网·节点内网」：请确认节点出站可访问 master_url，且主控已暴露 HTTPS"
	default:
		return "请确认 master_url 可从本机访问（含 /api 前缀），并检查防火墙与反向代理"
	}
}
