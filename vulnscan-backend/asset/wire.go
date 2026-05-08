package asset

import (
	assetContract "vulnscan-backend/asset/asset-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceAsset,
	NewHandlerAsset,
	NewEnrichHandler,
	NewAsset,
	wire.Bind(new(assetContract.ServiceAsset), new(*serviceAsset)),
)
