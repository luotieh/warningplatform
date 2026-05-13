package sitemonitor

import (
	"vulnscan-backend/sitemonitor/contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceMonitor,
	NewHandlerMonitor,
	NewMonitor,
	wire.Bind(new(contract.ServiceMonitor), new(*serviceMonitor)),
)
