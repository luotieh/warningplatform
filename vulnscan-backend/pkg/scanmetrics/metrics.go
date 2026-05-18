package scanmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// mode: database | filesystem（与 NucleiModule 模板来源一致）
// outcome: success | execute_error | init_error | skipped_no_templates | skipped_no_targets | config_error
var (
	nucleiRuns = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vulnscan",
			Subsystem: "nuclei",
			Name:      "runs_total",
			Help:      "Nuclei 模块执行次数（按模板来源与结果分类）。",
		},
		[]string{"mode", "outcome"},
	)
	nucleiRunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "vulnscan",
			Subsystem: "nuclei",
			Name:      "run_duration_seconds",
			Help:      "Nuclei 单次运行耗时（秒）。",
			Buckets:   []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300},
		},
		[]string{"mode", "outcome"},
	)
	nucleiFindings = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vulnscan",
			Subsystem: "nuclei",
			Name:      "findings_total",
			Help:      "Nuclei 回调产出的 finding 条数累计。",
		},
		[]string{"mode", "outcome"},
	)
)

// RecordNucleiRun 记录一次 Nuclei 运行（含跳过、初始化失败等终态）。
func RecordNucleiRun(mode, outcome string, durationSecs float64, findings int) {
	if mode == "" {
		mode = "unknown"
	}
	if outcome == "" {
		outcome = "unknown"
	}
	nucleiRuns.WithLabelValues(mode, outcome).Inc()
	if findings > 0 {
		nucleiFindings.WithLabelValues(mode, outcome).Add(float64(findings))
	}
	if durationSecs > 0 && (outcome == "success" || outcome == "execute_error") {
		nucleiRunDuration.WithLabelValues(mode, outcome).Observe(durationSecs)
	}
}
