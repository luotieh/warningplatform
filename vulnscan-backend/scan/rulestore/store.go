package rulestore

import (
	"log/slog"
	"regexp"
	"sync"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// CompiledRule 编译后的规则（正则已预编译）
type CompiledRule struct {
	model.ScanRule
	PatternRe *regexp.Regexp
	VersionRe *regexp.Regexp
}

// Store 通用规则库 — 支持 DB + 内置默认 + 热重载
type Store struct {
	db    *gorm.DB
	mu    sync.RWMutex
	rules map[string][]*CompiledRule // ruleType -> compiled rules
}

func New(db *gorm.DB) *Store {
	s := &Store{
		db:    db,
		rules: make(map[string][]*CompiledRule),
	}
	s.loadAll()
	return s
}

func NewWithoutDB() *Store {
	s := &Store{
		rules: make(map[string][]*CompiledRule),
	}
	s.loadBuiltins()
	return s
}

// Get 获取指定类型的所有活跃规则
func (s *Store) Get(ruleType string) []*CompiledRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules[ruleType]
}

// Reload 热重载（从 DB 重新加载后合并内置规则）
func (s *Store) Reload() {
	s.loadAll()
}

func (s *Store) loadAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = make(map[string][]*CompiledRule)
	s.loadBuiltinsLocked()

	if s.db == nil {
		return
	}

	var dbRules []model.ScanRule
	if err := s.db.Where("status = ?", model.RuleStatusActive).Order("priority DESC").Find(&dbRules).Error; err != nil {
		slog.Warn("规则库DB加载失败，仅使用内置规则", "error", err)
		return
	}

	for i := range dbRules {
		compiled := compile(&dbRules[i])
		if compiled == nil {
			continue
		}
		s.rules[dbRules[i].RuleType] = append(s.rules[dbRules[i].RuleType], compiled)
	}

	for t, rs := range s.rules {
		slog.Info("规则库已加载", "type", t, "count", len(rs))
	}
}

func (s *Store) loadBuiltins() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadBuiltinsLocked()
}

func (s *Store) loadBuiltinsLocked() {
	for _, def := range builtinJSRules {
		if c := compile(&def); c != nil {
			s.rules[model.RuleTypeJSAnalyze] = append(s.rules[model.RuleTypeJSAnalyze], c)
		}
	}
	for _, def := range builtinWAFRules {
		if c := compile(&def); c != nil {
			s.rules[model.RuleTypeWAFDetect] = append(s.rules[model.RuleTypeWAFDetect], c)
		}
	}
	for _, def := range builtinTechRules {
		if c := compile(&def); c != nil {
			s.rules[model.RuleTypeTechDetect] = append(s.rules[model.RuleTypeTechDetect], c)
		}
	}
}

func compile(rule *model.ScanRule) *CompiledRule {
	patternRe, err := regexp.Compile(rule.MatchPattern)
	if err != nil {
		slog.Warn("规则正则编译失败，已跳过", "name", rule.Name, "pattern", rule.MatchPattern, "error", err)
		return nil
	}

	cr := &CompiledRule{
		ScanRule:  *rule,
		PatternRe: patternRe,
	}

	if rule.VersionPattern != "" {
		if vr, err := regexp.Compile(rule.VersionPattern); err == nil {
			cr.VersionRe = vr
		}
	}

	return cr
}
