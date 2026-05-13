package report

import "github.com/google/wire"

var WireSet = wire.NewSet(
	NewServiceReport,
	NewHandler,
	NewReport,
)
