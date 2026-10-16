# M0 baseline

Base commit: 222c086ac69418539369e3b3b66180f4ccfc4382; branch: trafficanalysis-local-fix.
Tracked tree was clean. Existing untracked archives and documents are preserved.
`go test ./evidence ./traffic/... -count=1` and `go build ./traffic/...` passed before edits (log: .local/pipeline-v2-baseline-tests.log).

Existing route: prepareReportInputMode -> snapshot adapter -> 5 phase-one F -> 4 S -> phase-one recomputation -> report normalization/projection.
Reuse targets: SnapshotEvidenceInput, evidence.Engine, SemanticEngine, Normalize, EvaluatePhaseOne, ReportEvidenceBundle and AggregateRecord.

This baseline records functional verification only. No baseline latency, P50/P95, heap or token measurement was obtained in this step; these must not be inferred from test runtime.
