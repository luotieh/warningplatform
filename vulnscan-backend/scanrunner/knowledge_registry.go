package scanrunner

import (
	"log/slog"
	"sync"

	"gorm.io/gorm"

	"code.yt-security.com/public/scanengine/dict"
	"code.yt-security.com/public/scanengine/payload"
	"code.yt-security.com/public/scanengine/rulestore"

	"vulnscan-backend/knowledge/nuclei"
	rawpayload "vulnscan-backend/pkg/payload"
)

// KnowledgeRegistry 扫描引擎与知识库共享的单例：payload、规则、字典、PoC 缓存。
type KnowledgeRegistry struct {
	mu        sync.RWMutex
	db        *gorm.DB
	RawLoader *rawpayload.Loader
	Loader    payload.Provider
	Rules     *rulestore.Store
	Dict      *dict.Store
	Poc       *nuclei.PocStore
}

var (
	defaultRegistry *KnowledgeRegistry
	defaultRegMu    sync.RWMutex
)

// NewKnowledgeRegistry 创建并加载知识库数据（进程内共享）。
func NewKnowledgeRegistry(db *gorm.DB) *KnowledgeRegistry {
	var rs *rulestore.Store
	if db != nil {
		rs = rulestore.New(NewRuleStoreDataSourceAdapter(db))
	} else {
		rs = rulestore.New(nil)
	}

	var ds *dict.Store
	if db != nil {
		ds = dict.NewStore(NewDictDataSourceAdapter(db))
	} else {
		ds = dict.NewStore(nil)
	}

	rawLoader := rawpayload.NewLoader(db)
	if err := rawLoader.LoadAll(); err != nil {
		slog.Warn("[Knowledge] 数据文库 payload 加载失败", "error", err)
	}
	loader := NewPayloadAdapter(rawLoader)

	var poc *nuclei.PocStore
	if db != nil {
		poc = nuclei.NewPocStore(db)
	} else {
		poc = nuclei.NewPocStoreNoDB()
	}

	reg := &KnowledgeRegistry{
		db:        db,
		RawLoader: rawLoader,
		Loader:    loader,
		Rules:     rs,
		Dict:      ds,
		Poc:       poc,
	}
	ensureModulesRegistered()
	logKnowledgeBootstrap(db, ds, rs, rawLoader)
	return reg
}

// SetDefaultKnowledgeRegistry 供 DI 注入；扫描调度与数据文库 API 共用。
func SetDefaultKnowledgeRegistry(r *KnowledgeRegistry) {
	defaultRegMu.Lock()
	defaultRegistry = r
	defaultRegMu.Unlock()
}

// DefaultKnowledgeRegistry 返回已注入的共享注册表。
func DefaultKnowledgeRegistry() *KnowledgeRegistry {
	defaultRegMu.Lock()
	defer defaultRegMu.Unlock()
	return defaultRegistry
}

// NewModuleFactory 基于共享注册表构建模块工厂（运行中任务使用同一 loader/rules）。
func (r *KnowledgeRegistry) NewModuleFactory() *ModuleFactory {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return &ModuleFactory{
		db:     r.db,
		rs:     r.Rules,
		ds:     r.Dict,
		loader: r.Loader,
		reg:    r,
	}
}

// ReloadAll 数据文库 / PoC / 规则变更后热重载。
func (r *KnowledgeRegistry) ReloadAll() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.RawLoader.Reload(); err != nil {
		return err
	}
	r.Loader = NewPayloadAdapter(r.RawLoader)
	r.Rules.Reload()
	if r.Poc != nil {
		r.Poc.Invalidate()
	}
	slog.Info("[Knowledge] 热重载完成（payload + scan_rule + poc_cache）")
	logKnowledgeBootstrap(r.db, r.Dict, r.Rules, r.RawLoader)
	return nil
}
