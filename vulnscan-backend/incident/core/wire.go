package core

import (
	coreContract "vulnscan-backend/incident/core/core-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceCore,
	NewHandlerCore,
	wire.Bind(new(coreContract.ServiceCore), new(*serviceCore)),
)
