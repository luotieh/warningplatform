package incident

import (
	"vulnscan-backend/incident/audit"
	"vulnscan-backend/incident/core"
	"vulnscan-backend/incident/knowledge"
	"vulnscan-backend/incident/remediation"
	"vulnscan-backend/incident/sla"
	"vulnscan-backend/incident/stats"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	core.WireSet,
	audit.WireSet,
	remediation.WireSet,
	sla.WireSet,
	knowledge.WireSet,
	stats.WireSet,
	NewIncident,
)
