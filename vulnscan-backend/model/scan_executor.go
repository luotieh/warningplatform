package model

import (
	"fmt"
	"strings"
)

const ScanExecutorLocalID = "local"

func NormalizeScanExecutorNodeIDs(ids []string) []string {
	if len(ids) == 0 {
		return []string{ScanExecutorLocalID}
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return []string{ScanExecutorLocalID}
	}
	return out
}

func ScanExecutorNodeIDsFromParams(params JSONMap) []string {
	if params == nil {
		return []string{ScanExecutorLocalID}
	}
	raw, ok := params["executor_node_ids"]
	if !ok || raw == nil {
		return []string{ScanExecutorLocalID}
	}
	switch v := raw.(type) {
	case []string:
		return NormalizeScanExecutorNodeIDs(v)
	case []interface{}:
		ids := make([]string, 0, len(v))
		for _, item := range v {
			ids = append(ids, strings.TrimSpace(fmt.Sprint(item)))
		}
		return NormalizeScanExecutorNodeIDs(ids)
	default:
		return NormalizeScanExecutorNodeIDs([]string{fmt.Sprint(v)})
	}
}

func ScanTaskLocalExecutorOnly(params JSONMap) bool {
	ids := ScanExecutorNodeIDsFromParams(params)
	for _, id := range ids {
		if id != ScanExecutorLocalID {
			return false
		}
	}
	return len(ids) > 0
}
