package vuln

import (
	vulnContract "vulnscan-backend/vuln/vuln-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceVuln,
	NewHandlerVuln,
	NewVuln,
	wire.Bind(new(vulnContract.ServiceVuln), new(*serviceVuln)),
)
