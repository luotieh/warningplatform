package scanrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"
	"vulnscan-backend/scan/core"
)

type dagNode struct {
	stage    stageGroup
	index    int
	inDegree int32
	children []*dagNode
}

func buildDAG(stages []stageGroup) ([]*dagNode, bool) {
	nodes := make([]*dagNode, len(stages))
	nameIndex := make(map[string]int, len(stages))

	for i := range stages {
		nodes[i] = &dagNode{stage: stages[i], index: i}
		nameIndex[stages[i].name] = i
	}

	hasAnyDeps := false
	for i, s := range stages {
		for _, dep := range s.dependsOn {
			if parentIdx, ok := nameIndex[dep]; ok {
				nodes[parentIdx].children = append(nodes[parentIdx].children, nodes[i])
				nodes[i].inDegree++
				hasAnyDeps = true
			}
		}
	}

	return nodes, hasAnyDeps
}

type dagResult struct {
	nodeIndex int
	findings  []*core.Finding
	targets   []*core.Target
}

func (r *Runner) executeDAG(
	ctx context.Context,
	stages []stageGroup,
	targets []*core.Target,
	config map[string]interface{},
	cb StageCallbacks,
	engineOpts EngineOpts,
) {
	nodes, hasAnyDeps := buildDAG(stages)

	if !hasAnyDeps {
		r.executeSequential(ctx, stages, targets, config, cb, engineOpts)
		return
	}

	stageCtx := &StageContext{
		CompletedStages: make(map[string]StageResult),
		Params:          r.templateInstance.Params,
	}

	currentTargets := targets
	var targetsMu sync.RWMutex

	resultsCh := make(chan dagResult, len(nodes))
	var wg sync.WaitGroup

	runNode := func(n *dagNode) {
		defer wg.Done()

		select {
		case <-ctx.Done():
			resultsCh <- dagResult{nodeIndex: n.index}
			return
		default:
		}

		stage := n.stage

		if !ShouldRun(stage, stageCtx) {
			r.writeLog("info", fmt.Sprintf("阶段 [%s] 条件不满足，跳过", stage.name), stage.name, "")
			if cb.OnModuleDone != nil {
				for _, m := range stage.modules {
					cb.OnModuleDone(stage.name, m.ID())
				}
			}
			resultsCh <- dagResult{nodeIndex: n.index}
			return
		}

		r.progress.SetCurrentStage(stage.name)
		r.progress.SyncToDB(stage.name)
		r.publishEvent(NewStageEvent(r.task.ID, stage.name, "started"))

		moduleNames := make([]string, 0, len(stage.modules))
		for _, m := range stage.modules {
			moduleNames = append(moduleNames, m.ID())
		}
		r.writeLog("info",
			fmt.Sprintf("阶段 [%s] 开始，包含 %d 个模块: %v", stage.name, len(stage.modules), moduleNames),
			stage.name, "")

		stageConfig := mergeConfig(config, stage.config)
		timeout := r.moduleTimeout
		if stage.timeout > 0 {
			timeout = stage.timeout
		}

		targetsMu.RLock()
		stageTargets := currentTargets
		targetsMu.RUnlock()

		stageFindings, newTargets := ExecuteStageWithOpts(
			ctx, r.task.ID, stage, stageTargets, stageConfig, timeout, cb, engineOpts,
		)

		resultsCh <- dagResult{
			nodeIndex: n.index,
			findings:  stageFindings,
			targets:   newTargets,
		}
	}

	launchReady := func() {
		for _, node := range nodes {
			if atomic.LoadInt32(&node.inDegree) == 0 && atomic.CompareAndSwapInt32(&node.inDegree, 0, -1) {
				wg.Add(1)
				go runNode(node)
			}
		}
	}

	launchReady()

	completed := 0
	for completed < len(nodes) {
		select {
		case <-ctx.Done():
			r.progress.FinishTask(model.TaskStatusCancelled, "任务被取消")
			wg.Wait()
			return
		case res := <-resultsCh:
			completed++
			node := nodes[res.nodeIndex]
			stage := node.stage

			stageCtx.CompletedStages[stage.name] = StageResult{
				Findings: res.findings,
				Targets:  res.targets,
			}

			if len(res.targets) > 0 {
				targetsMu.Lock()
				currentTargets = r.enricher.EnrichTargets(currentTargets, res.targets)
				targetsMu.Unlock()
			}

			if isReconStage(stage.name) && len(res.findings) > 0 {
				products := extractDetectedProducts(res.findings, config)
				if len(products) > 0 {
					config["detected_products"] = products
				}
				wafs := extractDetectedWAFs(res.findings)
				if len(wafs) > 0 {
					config["detected_wafs"] = wafs
				}
			}

			r.logPocMatchDecisions(config, stage.name)
			r.applyEngineRuntimeGating(config, stageCtx)

			r.progress.SetScanned(len(targets))
			r.progress.IncrementStageDone()
			r.progress.SyncToDB(stage.name)
			r.publishEvent(NewStageEvent(r.task.ID, stage.name, "completed"))
			r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))

			r.writeLog("info",
				fmt.Sprintf("阶段 [%s] 完成 (%d/%d)，本阶段发现 %d 条结果",
					stage.name, completed, len(nodes), len(res.findings)),
				stage.name, "")

			slog.Info("[Runner] Stage 完成", "task", r.task.ID, "stage", stage.name,
				"stage_num", completed, "total_stages", len(nodes),
				"findings_in_stage", len(res.findings))

			for _, child := range node.children {
				if atomic.AddInt32(&child.inDegree, -1) == 0 {
					atomic.StoreInt32(&child.inDegree, -1)
					wg.Add(1)
					go runNode(child)
				}
			}
		}
	}

	wg.Wait()
}

func (r *Runner) executeSequential(
	ctx context.Context,
	stages []stageGroup,
	targets []*core.Target,
	config map[string]interface{},
	cb StageCallbacks,
	engineOpts EngineOpts,
) {
	currentTargets := targets

	stageCtx := &StageContext{
		CompletedStages: make(map[string]StageResult),
		Params:          r.templateInstance.Params,
	}

	for i, stage := range stages {
		select {
		case <-ctx.Done():
			r.progress.FinishTask(model.TaskStatusCancelled, "任务被取消")
			return
		default:
		}

		if !ShouldRun(stage, stageCtx) {
			r.writeLog("info", fmt.Sprintf("阶段 [%s] 条件不满足，跳过", stage.name), stage.name, "")
			if cb.OnModuleDone != nil {
				for _, m := range stage.modules {
					cb.OnModuleDone(stage.name, m.ID())
				}
			}
			continue
		}

		r.progress.SetCurrentStage(stage.name)
		r.progress.SyncToDB(stage.name)
		r.publishEvent(NewStageEvent(r.task.ID, stage.name, "started"))

		moduleNames := make([]string, 0, len(stage.modules))
		for _, m := range stage.modules {
			moduleNames = append(moduleNames, m.ID())
		}
		r.writeLog("info",
			fmt.Sprintf("阶段 [%s] 开始，包含 %d 个模块: %v", stage.name, len(stage.modules), moduleNames),
			stage.name, "")

		stageConfig := mergeConfig(config, stage.config)
		timeout := r.moduleTimeout
		if stage.timeout > 0 {
			timeout = stage.timeout
		}

		stageFindings, stageTargets := ExecuteStageWithOpts(
			ctx, r.task.ID, stage, currentTargets, stageConfig, timeout, cb, engineOpts,
		)

		stageCtx.CompletedStages[stage.name] = StageResult{
			Findings: stageFindings,
			Targets:  stageTargets,
		}

		if len(stageTargets) > 0 {
			currentTargets = r.enricher.EnrichTargets(currentTargets, stageTargets)
		}

		if isReconStage(stage.name) && len(stageFindings) > 0 {
			products := extractDetectedProducts(stageFindings, config)
			if len(products) > 0 {
				config["detected_products"] = products
				r.writeLog("info",
					fmt.Sprintf("检测到 %d 个产品/技术: %v", len(products), products),
					stage.name, "")
			}
			wafs := extractDetectedWAFs(stageFindings)
			if len(wafs) > 0 {
				config["detected_wafs"] = wafs
				r.writeLog("info",
					fmt.Sprintf("检测到 %d 个WAF: %v", len(wafs), wafs),
					stage.name, "")
			}
		}

		r.logPocMatchDecisions(config, stage.name)

		r.applyEngineRuntimeGating(config, stageCtx)

		r.progress.SetScanned(len(targets))
		r.progress.IncrementStageDone()
		r.progress.SyncToDB(stage.name)
		r.publishEvent(NewStageEvent(r.task.ID, stage.name, "completed"))
		r.publishEvent(NewProgressEvent(r.task.ID, *r.progress.Get()))

		r.writeLog("info",
			fmt.Sprintf("阶段 [%s] 完成 (%d/%d)，本阶段发现 %d 条结果",
				stage.name, i+1, len(stages), len(stageFindings)),
			stage.name, "")

		select {
		case <-ctx.Done():
			r.writeLog("warn", "任务被取消", "", "")
			r.publishEvent(NewDoneEvent(r.task.ID, model.TaskStatusCancelled, "任务被取消"))
			r.progress.FinishTask(model.TaskStatusCancelled, "任务被取消")
			return
		default:
		}

		slog.Info("[Runner] Stage 完成", "task", r.task.ID, "stage", stage.name,
			"stage_num", i+1, "total_stages", len(stages),
			"findings_in_stage", len(stageFindings))
	}
}

// logPocMatchDecisions writes PoC match decision log entries and clears the transient config key.
func (r *Runner) logPocMatchDecisions(config map[string]interface{}, stage string) {
	raw, ok := config["_poc_match_decisions"]
	if !ok {
		return
	}
	delete(config, "_poc_match_decisions")

	decisions, ok := raw.([]nuclei.MatchDecision)
	if !ok || len(decisions) == 0 {
		return
	}

	matchedCount := 0
	for _, d := range decisions {
		if d.Matched {
			matchedCount++
		}
	}

	summary := fmt.Sprintf("[PoC匹配] 共评估 %d 条 PoC，命中 %d 条", len(decisions), matchedCount)
	r.writeLog("info", summary, stage, "nuclei-poc")

	data, _ := json.Marshal(decisions)
	r.writeLog("debug", string(data), stage, "nuclei-poc-decisions")
}
