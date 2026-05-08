package boot

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"code.yt-security.com/public/core/v2/cache"
	cachemem "code.yt-security.com/public/core/v2/cache/memory"
	cacheredis "code.yt-security.com/public/core/v2/cache/redis"
	goredis "github.com/redis/go-redis/v9"
)

type throttledRedisLogger struct {
	mu       sync.Mutex
	lastLog  time.Time
	interval time.Duration
}

func (l *throttledRedisLogger) Printf(_ context.Context, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastLog) < l.interval {
		return
	}
	l.lastLog = now
	slog.Warn("[redis] " + fmt.Sprintf(format, v...))
}

func LoadCache(config *Config) cache.Cache {
	goredis.SetLogger(&throttledRedisLogger{interval: 30 * time.Second})

	if config.Cache.Host != "" {
		addr := fmt.Sprintf("%s:%d", config.Cache.Host, config.Cache.Port)
		if config.Cache.Port == 0 {
			addr = config.Cache.Host + ":6379"
		}
		c, err := cacheredis.New(cacheredis.Options{
			Addr:     addr,
			Username: config.Cache.Username,
			Password: config.Cache.Password,
			DB:       config.Cache.DB,
			Prefix:   config.Cache.Prefix,
		})
		if err != nil {
			slog.Error("[!] Redis缓存加载失败，回退到内存缓存", "error", err)
			return cachemem.New(cachemem.Options{Capacity: 10000})
		}
		slog.Info("[+] Redis缓存加载成功")
		return c
	}

	slog.Info("[+] 内存缓存加载成功")
	return cachemem.New(cachemem.Options{Capacity: 10000})
}
