//go:build wireinject

package di

import (
	"vulnscan-backend/asset"
	"vulnscan-backend/assetmgr"
	"vulnscan-backend/boot"
	"vulnscan-backend/circular"
	"vulnscan-backend/cluster"
	"vulnscan-backend/incident"
	"vulnscan-backend/organize"
	"vulnscan-backend/sitemonitor"
	"vulnscan-backend/tagging"
	"vulnscan-backend/task"
	"vulnscan-backend/vuln"

	"github.com/google/wire"
)

func InitializeHandlers() *Handlers {
	wire.Build(
		boot.LoadConfig,
		boot.LoadProduct,
		boot.LoadCache,
		boot.LoadWeb,
		boot.LoadDB,
		boot.LoadIAM,
		boot.LoadNats,

		asset.WireSet,
		task.WireSet,
		vuln.WireSet,
		cluster.WireSet,
		tagging.Set,
		organize.Set,
		assetmgr.Set,
		sitemonitor.WireSet,
		circular.WireSet,
		incident.WireSet,

		wire.Struct(new(Handlers), "Config", "Web", "DB", "Cache", "Product", "IAM",
			"Asset", "Task", "Vuln", "Cluster", "Tagging", "Organize", "AssetMgr", "SiteMonitor", "Circular", "Incident"),
	)
	return nil
}
