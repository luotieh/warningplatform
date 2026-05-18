package nodecapacity

import "testing"

func TestComputeReserveAndLimits(t *testing.T) {
	snap := Compute(Config{
		ReserveRatio: 0.10,
		MemPerTaskMB: 512,
		MinCapacity:  1,
	})

	if snap.Capacity < 1 {
		t.Fatalf("capacity=%d", snap.Capacity)
	}
	if snap.Capacity > snap.LimitByCPU || snap.Capacity > snap.LimitByMemory {
		t.Fatalf("capacity should be min of limits: cap=%d cpu=%d mem=%d", snap.Capacity, snap.LimitByCPU, snap.LimitByMemory)
	}
	if snap.ReserveRatio != 0.10 {
		t.Fatalf("reserve ratio")
	}
}

func TestComputeMaxCap(t *testing.T) {
	snap := Compute(Config{
		ReserveRatio: 0.10,
		MemPerTaskMB: 1,
		MinCapacity:  1,
		MaxCapacity:  3,
	})
	if snap.Capacity > 3 {
		t.Fatalf("expected max 3, got %d", snap.Capacity)
	}
}
