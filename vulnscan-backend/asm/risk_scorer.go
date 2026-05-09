package asm

type RiskScorer struct {
	baseScore     int
	typeWeights   map[string]int
	sourceWeights map[string]int
}

func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		baseScore: 30,
		typeWeights: map[string]int{
			"ip":        20,
			"domain":    10,
			"subdomain": 15,
			"url":       30,
			"port":      25,
			"service":   35,
		},
		sourceWeights: map[string]int{
			"dns":               5,
			"cert-transparency": 10,
			"rdns":              5,
			"port-scan":         15,
			"service-probe":     20,
			"passive":           5,
		},
	}
}

func (s *RiskScorer) Calculate(asset DiscoveredAsset) int {
	score := s.baseScore

	if w, ok := s.typeWeights[asset.Type]; ok {
		score += w
	}

	for source, weight := range s.sourceWeights {
		if asset.Source == source {
			score += weight
			break
		}
	}

	if asset.Attributes != nil {
		if _, ok := asset.Attributes["high_risk_port"]; ok {
			score += 20
		}
		if _, ok := asset.Attributes["known_vuln"]; ok {
			score += 30
		}
		if _, ok := asset.Attributes["internal"]; ok {
			score -= 10
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
