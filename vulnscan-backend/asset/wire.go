package asset

import (
	assetContract "vulnscan-backend/asset/asset-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceAsset,
	NewScreenshotService,
	NewHandlerAsset,
	NewEnrichHandler,
	NewDiscoveryHandler,
	NewAsset,
	wire.Bind(new(assetContract.ServiceAsset), new(*serviceAsset)),
)
