package audit

import (
	auditContract "vulnscan-backend/incident/audit/audit-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceAudit,
	NewHandlerAudit,
	wire.Bind(new(auditContract.ServiceAudit), new(*serviceAudit)),
)
