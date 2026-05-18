package fprule

import (
	fpruleContract "vulnscan-backend/fprule/fprule-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceFPRule,
	NewHandlerFPRule,
	NewFPRule,
	wire.Bind(new(fpruleContract.ServiceFPRule), new(*serviceFPRule)),
)
