package remediation

import (
	remediationContract "vulnscan-backend/incident/remediation/remediation-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceRemediation,
	NewHandlerRemediation,
	wire.Bind(new(remediationContract.ServiceRemediation), new(*serviceRemediation)),
)
