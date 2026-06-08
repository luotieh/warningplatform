package boot

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"code.yt-security.com/public/core/config"
)

type ConfigWatcher struct {
	path      string
	interval  time.Duration
	lastHash  string
	current   atomic.Value
	mu        sync.RWMutex
	callbacks []func(*Config)
	stopCh    chan struct{}
}

func NewConfigWatcher(path string, initial *Config) *ConfigWatcher {
	cw := &ConfigWatcher{
		path:     path,
		interval: 10 * time.Second,
		stopCh:   make(chan struct{}),
	}
	cw.current.Store(initial)
	cw.lastHash = cw.fileHash()
	return cw
}

func (cw *ConfigWatcher) OnChange(fn func(*Config)) {
	cw.mu.Lock()
	cw.callbacks = append(cw.callbacks, fn)
	cw.mu.Unlock()
}

func (cw *ConfigWatcher) Current() *Config {
	return cw.current.Load().(*Config)
}

func (cw *ConfigWatcher) Start() {
	go func() {
		ticker := time.NewTicker(cw.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cw.check()
			case <-cw.stopCh:
				return
			}
		}
	}()
	slog.Info("[+] 配置热更新监听已启动", "path", cw.path, "interval", cw.interval)
}

func (cw *ConfigWatcher) Stop() {
	close(cw.stopCh)
}

func (cw *ConfigWatcher) check() {
	newHash := cw.fileHash()
	if newHash == "" || newHash == cw.lastHash {
		return
	}

	slog.Info("[*] 检测到配置文件变更，正在重新加载...", "path", cw.path)

	newConfig := loadConfigFromPath(cw.path)
	if newConfig == nil {
		slog.Error("[!] 配置文件重新加载失败，保持当前配置")
		return
	}

	cw.lastHash = newHash
	cw.current.Store(newConfig)

	cw.mu.RLock()
	callbacks := make([]func(*Config), len(cw.callbacks))
	copy(callbacks, cw.callbacks)
	cw.mu.RUnlock()

	for _, fn := range callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("[!] 配置变更回调 panic", "error", r)
				}
			}()
			fn(newConfig)
		}()
	}

	slog.Info("[+] 配置文件已热更新")
}

func (cw *ConfigWatcher) fileHash() string {
	data, err := os.ReadFile(cw.path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func loadConfigFromPath(path string) *Config {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[!] loadConfigFromPath panic", "error", r)
		}
	}()

	var mConfig Config
	if err := config.Load(path, &mConfig); err != nil {
		slog.Error("[!] 配置文件重加载失败", "error", err, "path", path)
		return nil
	}

	if mConfig.Cache.Prefix == "" {
		mConfig.Cache.Prefix = "vs:"
	}
	return &mConfig
}
