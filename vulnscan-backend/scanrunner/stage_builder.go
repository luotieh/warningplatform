package scanrunner

import (
	"time"

	"vulnscan-backend/scan/core"
	"vulnscan-backend/template/engine"
)

type stageGroup struct {
	name      string
	modules   []core.ScanModule
	parallel  bool
	condition *engine.StageCondition
	dependsOn []string
	config    map[string]interface{}
	timeout   time.Duration
}
