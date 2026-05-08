package disposal

import (
	disposalContract "vulnscan-backend/circular/disposal/disposal-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceDisposal,
	NewHandlerDisposal,
	wire.Bind(new(disposalContract.ServiceDisposal), new(*serviceDisposal)),
)
