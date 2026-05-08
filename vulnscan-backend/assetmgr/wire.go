package assetmgr

import (
	ac "vulnscan-backend/assetmgr/assetmgr-contract"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	NewServiceLifecycle,
	NewServiceRisk,
	NewServiceAlert,
	NewServiceVerify,
	NewServiceComplianceItem,
	NewServiceComplianceTemplate,
	NewServiceCheckResult,
	NewServiceResponsible,
	NewServiceIntegration,
	NewServiceWorkflow,
	NewHandler,
	NewAssetMgr,
	wire.Bind(new(ac.ServiceLifecycle), new(*serviceLifecycle)),
	wire.Bind(new(ac.ServiceRisk), new(*serviceRisk)),
	wire.Bind(new(ac.ServiceAlert), new(*serviceAlert)),
	wire.Bind(new(ac.ServiceVerify), new(*serviceVerify)),
	wire.Bind(new(ac.ServiceComplianceItem), new(*serviceComplianceItem)),
	wire.Bind(new(ac.ServiceComplianceTemplate), new(*serviceComplianceTemplate)),
	wire.Bind(new(ac.ServiceCheckResult), new(*serviceCheckResult)),
	wire.Bind(new(ac.ServiceResponsible), new(*serviceResponsible)),
	wire.Bind(new(ac.ServiceIntegration), new(*serviceIntegration)),
	wire.Bind(new(ac.ServiceWorkflow), new(*serviceWorkflow)),
)
