package scanrunner

import "strings"

func ShouldRun(stage stageGroup, ctx *StageContext) bool {
	for _, dep := range stage.dependsOn {
		if _, ok := ctx.CompletedStages[dep]; !ok {
			return false
		}
	}

	if stage.condition == nil {
		return true
	}

	if stage.condition.PrevStageHasFindings {
		hasFindings := false
		for _, r := range ctx.CompletedStages {
			if len(r.Findings) > 0 {
				hasFindings = true
				break
			}
		}
		if !hasFindings {
			return false
		}
	}

	if stage.condition.PrevStageMinTargets > 0 {
		totalTargets := 0
		for _, r := range ctx.CompletedStages {
			totalTargets += len(r.Targets)
		}
		if totalTargets < stage.condition.PrevStageMinTargets {
			return false
		}
	}

	if stage.condition.Expression != "" {
		if !evalBoolExpr(stage.condition.Expression) {
			return false
		}
	}

	return true
}

func evalBoolExpr(expr string) bool {
	s := strings.TrimSpace(strings.ToLower(expr))
	return s == "true" || s == "1" || s == "yes"
}
