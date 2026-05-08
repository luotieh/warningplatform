package sitemonitor

import (
	mc "vulnscan-backend/sitemonitor/sitemonitor-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceMonitor,
	NewHandlerMonitor,
	NewMonitor,
	wire.Bind(new(mc.ServiceMonitor), new(*serviceMonitor)),
)
