package notify

import "github.com/google/wire"

var WireSet = wire.NewSet(
	NewServiceNotify,
	NewHandler,
	NewNotifyRoutes,
)
