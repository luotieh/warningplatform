package dashboard

import "github.com/google/wire"

var WireSet = wire.NewSet(
	NewHandler,
	NewDashboard,
)
