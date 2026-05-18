package scanrunner

import "testing"

func TestNormalizeExecutorNodeIDsDefaultLocal(t *testing.T) {
	got := NormalizeExecutorNodeIDs(nil)
	if len(got) != 1 || got[0] != ExecutorLocalID {
		t.Fatalf("got %v", got)
	}
}

func TestSinglePinnedWorkerID(t *testing.T) {
	if id := SinglePinnedWorkerID([]string{"w-1"}); id != "w-1" {
		t.Fatalf("got %q", id)
	}
	if id := SinglePinnedWorkerID([]string{ExecutorLocalID, "w-1"}); id != "w-1" {
		t.Fatalf("local+single worker should pin worker, got %q", id)
	}
	if id := SinglePinnedWorkerID([]string{"w-1", "w-2"}); id != "" {
		t.Fatalf("multi worker should shard, got pin %q", id)
	}
}

func TestScanTaskLocalExecutorOnly(t *testing.T) {
	if !ScanTaskLocalExecutorOnly(map[string]interface{}{"executor_node_ids": []interface{}{"local"}}) {
		t.Fatal("expected local only")
	}
}
