package nodecapacity

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

const defaultReserveRatio = 0.10

// Config 节点并发容量估算参数。
type Config struct {
	// ReserveRatio 预留给操作系统与其它进程的占比（默认 0.10 = 10%）
	ReserveRatio float64
	// MemPerTaskMB 单个并发扫描任务估算内存占用（MB）
	MemPerTaskMB float64
	MinCapacity  int
	MaxCapacity  int // 0 表示不限制上限
}

// Snapshot 计算结果与依据。
type Snapshot struct {
	Capacity       int     `json:"capacity"`
	LogicalCPUs    int     `json:"logical_cpus"`
	TotalMemoryMB  float64 `json:"total_memory_mb"`
	UsableCPUs     float64 `json:"usable_cpus"`
	UsableMemoryMB float64 `json:"usable_memory_mb"`
	LimitByCPU     int     `json:"limit_by_cpu"`
	LimitByMemory  int     `json:"limit_by_memory"`
	ReserveRatio   float64 `json:"reserve_ratio"`
	MemPerTaskMB   float64 `json:"mem_per_task_mb"`
}

func DefaultConfig() Config {
	cfg := Config{
		ReserveRatio: defaultReserveRatio,
		MemPerTaskMB: 512,
		MinCapacity:  1,
		MaxCapacity:  0,
	}
	if v := strings.TrimSpace(os.Getenv("VULNSCAN_NODE_RESERVE_RATIO")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f < 1 {
			cfg.ReserveRatio = f
		}
	}
	if v := strings.TrimSpace(os.Getenv("VULNSCAN_NODE_MEM_PER_TASK_MB")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.MemPerTaskMB = f
		}
	}
	if v := strings.TrimSpace(os.Getenv("VULNSCAN_NODE_MAX_CAPACITY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxCapacity = n
		}
	}
	return cfg
}

// Compute 根据 CPU 核数与内存估算可承载的并发任务数（预留 ReserveRatio 系统余量）。
func Compute(cfg Config) Snapshot {
	if cfg.ReserveRatio < 0 || cfg.ReserveRatio >= 1 {
		cfg.ReserveRatio = defaultReserveRatio
	}
	if cfg.MemPerTaskMB <= 0 {
		cfg.MemPerTaskMB = 512
	}
	if cfg.MinCapacity <= 0 {
		cfg.MinCapacity = 1
	}

	usableRatio := 1.0 - cfg.ReserveRatio
	logical := runtime.NumCPU()
	if n, err := cpu.Counts(true); err == nil && n > 0 {
		logical = n
	}

	totalMemMB := float64(0)
	if vm, err := mem.VirtualMemory(); err == nil && vm != nil && vm.Total > 0 {
		totalMemMB = float64(vm.Total) / 1024 / 1024
	}

	usableCPUs := float64(logical) * usableRatio
	usableMemMB := totalMemMB * usableRatio

	limitCPU := int(math.Floor(usableCPUs))
	if limitCPU < cfg.MinCapacity {
		limitCPU = cfg.MinCapacity
	}

	limitMem := cfg.MinCapacity
	if cfg.MemPerTaskMB > 0 && usableMemMB > 0 {
		limitMem = int(math.Floor(usableMemMB / cfg.MemPerTaskMB))
	}
	if limitMem < cfg.MinCapacity {
		limitMem = cfg.MinCapacity
	}

	capacity := limitCPU
	if limitMem < capacity {
		capacity = limitMem
	}
	if cfg.MaxCapacity > 0 && capacity > cfg.MaxCapacity {
		capacity = cfg.MaxCapacity
	}

	return Snapshot{
		Capacity:       capacity,
		LogicalCPUs:    logical,
		TotalMemoryMB:  totalMemMB,
		UsableCPUs:     usableCPUs,
		UsableMemoryMB: usableMemMB,
		LimitByCPU:     limitCPU,
		LimitByMemory:  limitMem,
		ReserveRatio:   cfg.ReserveRatio,
		MemPerTaskMB:   cfg.MemPerTaskMB,
	}
}

// CPUUsagePercent 返回系统 CPU 使用率（0–100）。
func CPUUsagePercent() float64 {
	percents, err := cpu.Percent(0, false)
	if err != nil || len(percents) == 0 {
		return 0
	}
	return percents[0]
}

// MemoryUsagePercent 返回系统内存使用率（0–100）。
func MemoryUsagePercent() float64 {
	vm, err := mem.VirtualMemory()
	if err != nil || vm == nil {
		return 0
	}
	return vm.UsedPercent
}
