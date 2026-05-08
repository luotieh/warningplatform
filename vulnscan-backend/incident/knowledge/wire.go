package knowledge

import (
	knowledgeContract "vulnscan-backend/incident/knowledge/knowledge-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceKnowledge,
	NewHandlerKnowledge,
	wire.Bind(new(knowledgeContract.ServiceKnowledge), new(*serviceKnowledge)),
)
