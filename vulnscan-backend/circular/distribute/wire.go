package distribute

import (
	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceDistribute,
	NewHandlerDistribute,
	wire.Bind(new(distributeContract.ServiceDistribute), new(*serviceDistribute)),
)
