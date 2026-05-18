package exclusion

import (
	exclusionContract "vulnscan-backend/exclusion/exclusion-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceExclusion,
	NewHandlerExclusion,
	NewExclusion,
	wire.Bind(new(exclusionContract.ServiceExclusion), new(*serviceExclusion)),
)
