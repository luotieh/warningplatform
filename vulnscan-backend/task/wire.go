package task

import (
	taskContract "vulnscan-backend/task/task-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceTask,
	NewHandlerTask,
	NewTask,
	wire.Bind(new(taskContract.ServiceTask), new(*serviceTask)),
)
