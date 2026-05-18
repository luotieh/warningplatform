package scanrunner

import (
	"testing"

	"vulnscan-backend/model"
)

func TestWorkerTargetShardingEnabled(t *testing.T) {
	t.Parallel()
	if workerTargetShardingEnabled(nil) {
		t.Fatal("nil")
	}
	if workerTargetShardingEnabled(model.JSONMap{"worker_target_sharding": false}) {
		t.Fatal("false")
	}
	if !workerTargetShardingEnabled(model.JSONMap{"worker_target_sharding": true}) {
		t.Fatal("true")
	}
	if !workerTargetShardingEnabled(model.JSONMap{"worker_target_sharding": "1"}) {
		t.Fatal("1")
	}
}

func TestIsScanTaskTerminalStatus(t *testing.T) {
	t.Parallel()
	if !isScanTaskTerminalStatus(model.TaskStatusCompleted) {
		t.Fatal("completed")
	}
	if !isScanTaskTerminalStatus(model.TaskStatusPartial) {
		t.Fatal("partial")
	}
	if isScanTaskTerminalStatus(model.TaskStatusRunning) {
		t.Fatal("running")
	}
}
