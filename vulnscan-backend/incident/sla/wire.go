package sla

import (
	slaContract "vulnscan-backend/incident/sla/sla-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceSLA,
	NewHandlerSLA,
	wire.Bind(new(slaContract.ServiceSLA), new(*serviceSLA)),
)
