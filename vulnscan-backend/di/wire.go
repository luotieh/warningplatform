//go:build wireinject

package di

import (
	"vulnscan-backend/asset"
	"vulnscan-backend/assetmgr"
	"vulnscan-backend/boot"
	"vulnscan-backend/circular"
	"vulnscan-backend/cluster"
	"vulnscan-backend/compliance"
	"vulnscan-backend/dashboard"
	"vulnscan-backend/exclusion"
	"vulnscan-backend/fprule"
	"vulnscan-backend/incident"
	"vulnscan-backend/notify"
	"vulnscan-backend/organize"
	"vulnscan-backend/report"
	sitemon "vulnscan-backend/sitemonitor"
	"vulnscan-backend/tagging"
	"vulnscan-backend/task"
	"vulnscan-backend/vuln"

	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/ai"
	"github.com/google/wire"
)

func provideChatService(client *iamsdk.Client) *ai.ChatService {
	return client.Chat
}

func InitializeHandlers() *Handlers {
	wire.Build(
		boot.LoadConfig,
		boot.LoadProduct,
		boot.LoadCache,
		boot.LoadWeb,
		boot.LoadDB,
		boot.LoadIAM,
		boot.LoadNats,
		provideChatService,

		asset.WireSet,
		task.WireSet,
		vuln.WireSet,
		cluster.WireSet,
		tagging.Set,
		organize.Set,
		assetmgr.Set,
		sitemon.WireSet,
		circular.WireSet,
		incident.WireSet,
		dashboard.WireSet,
		notify.WireSet,
		compliance.WireSet,
		report.WireSet,
		exclusion.WireSet,
		fprule.WireSet,

		wire.Struct(new(Handlers), "Config", "Web", "DB", "Cache", "Product", "IAM",
			"Asset", "Task", "Vuln", "Cluster", "Tagging", "Organize", "AssetMgr", "SiteMonitor", "Circular", "Incident",
			"Dashboard", "Notify", "Compliance", "Report", "Exclusion", "FPRule"),
	)
	return nil
}
