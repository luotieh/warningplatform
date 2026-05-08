package ledger

import (
	ledgerContract "vulnscan-backend/circular/ledger/ledger-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceLedger,
	NewHandlerLedger,
	wire.Bind(new(ledgerContract.ServiceLedger), new(*serviceLedger)),
)
