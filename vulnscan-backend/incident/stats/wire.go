package stats

import (
	statsContract "vulnscan-backend/incident/stats/stats-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceStats,
	NewHandlerStats,
	wire.Bind(new(statsContract.ServiceStats), new(*serviceStats)),
)
