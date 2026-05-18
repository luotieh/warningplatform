package scanrunner

import (
	"vulnscan-backend/model"
)

// ExecutorLocalID 与 GET /nodes 返回的本地引擎 id 一致。
const ExecutorLocalID = model.ScanExecutorLocalID

func NormalizeExecutorNodeIDs(ids []string) []string {
	return model.NormalizeScanExecutorNodeIDs(ids)
}

func ExecutorNodeIDsFromParams(params model.JSONMap) []string {
	return model.ScanExecutorNodeIDsFromParams(params)
}

func RemoteWorkerIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range NormalizeExecutorNodeIDs(ids) {
		if id != "" && id != ExecutorLocalID {
			out = append(out, id)
		}
	}
	return out
}

func IsLocalExecutorOnly(ids []string) bool {
	return len(RemoteWorkerIDs(NormalizeExecutorNodeIDs(ids))) == 0
}

func SinglePinnedWorkerID(ids []string) string {
	remote := RemoteWorkerIDs(NormalizeExecutorNodeIDs(ids))
	if len(remote) == 1 {
		return remote[0]
	}
	return ""
}

func ScanTaskLocalExecutorOnly(params model.JSONMap) bool {
	return model.ScanTaskLocalExecutorOnly(params)
}

func ApplyExecutorNodeParams(params model.JSONMap, ids []string) {
	if params == nil {
		return
	}
	ids = NormalizeExecutorNodeIDs(ids)
	params["executor_node_ids"] = ids
	if IsLocalExecutorOnly(ids) {
		params["executor_local_only"] = true
	} else {
		delete(params, "executor_local_only")
	}
}

func filterWorkersByAllowed(workers []model.WorkerNode, allowed []string) []model.WorkerNode {
	allowed = RemoteWorkerIDs(allowed)
	if len(allowed) == 0 {
		return workers
	}
	set := make(map[string]struct{}, len(allowed))
	for _, id := range allowed {
		set[id] = struct{}{}
	}
	out := make([]model.WorkerNode, 0, len(allowed))
	for _, w := range workers {
		if _, ok := set[w.ID]; ok {
			out = append(out, w)
		}
	}
	return out
}
