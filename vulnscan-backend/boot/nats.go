package boot

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type NatsClient struct {
	Conn     *nats.Conn
	JS       jetstream.JetStream
	KV       jetstream.KeyValue
	ObjStore jetstream.ObjectStore
	Config   NatsConfig
}

func LoadNats(config *Config) *NatsClient {
	if config.Nats.URL == "" {
		slog.Debug("[NATS] 未配置，站点监控消息功能不可用")
		return &NatsClient{Config: config.Nats}
	}

	opts := []nats.Option{
		nats.Name("vulnscan-backend"),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("[NATS] 连接断开", "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			slog.Info("[NATS] 已重连", "url", nc.ConnectedUrl())
		}),
	}

	switch {
	case config.Nats.CredsFile != "":
		opts = append(opts, nats.UserCredentials(config.Nats.CredsFile))
	case config.Nats.NKeySeed != "":
		opt, err := nats.NkeyOptionFromSeed(config.Nats.NKeySeed)
		if err != nil {
			slog.Error("[NATS] NKey 种子加载失败", "error", err)
		} else {
			opts = append(opts, opt)
		}
	case config.Nats.Token != "":
		opts = append(opts, nats.Token(config.Nats.Token))
	case config.Nats.User != "":
		opts = append(opts, nats.UserInfo(config.Nats.User, config.Nats.Password))
	}

	if config.Nats.TLSCA != "" || config.Nats.TLSCert != "" {
		tlsCfg, err := buildNatsTLS(config.Nats.TLSCA, config.Nats.TLSCert, config.Nats.TLSKey)
		if err != nil {
			slog.Error("[NATS] TLS 配置失败", "error", err)
		} else {
			opts = append(opts, nats.Secure(tlsCfg))
		}
	}

	timeout := 5 * time.Second
	if config.Nats.ConnectTimeout > 0 {
		timeout = time.Duration(config.Nats.ConnectTimeout) * time.Second
	}
	opts = append(opts, nats.Timeout(timeout))

	nc, err := nats.Connect(config.Nats.URL, opts...)
	if err != nil {
		slog.Error("[NATS] 连接失败", "url", config.Nats.URL, "error", err)
		return &NatsClient{Config: config.Nats}
	}
	slog.Info("[+] NATS 就绪", "url", nc.ConnectedUrl())

	client := &NatsClient{Conn: nc, Config: config.Nats}
	ctx := context.Background()

	js, err := jetstream.New(nc)
	if err != nil {
		slog.Error("[NATS] JetStream初始化失败", "error", err)
		return client
	}
	client.JS = js

	taskStream := config.Nats.TaskStream
	if taskStream == "" {
		taskStream = "MONITOR_TASKS"
	}
	if _, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      taskStream,
		Subjects:  []string{"monitor.task.*"},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.WorkQueuePolicy,
		MaxAge:    2 * time.Hour,
	}); err != nil {
		slog.Error("[NATS] Task Stream创建失败", "name", taskStream, "error", err)
	}

	resultStream := config.Nats.ResultStream
	if resultStream == "" {
		resultStream = "MONITOR_RESULTS"
	}
	if _, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      resultStream,
		Subjects:  []string{"monitor.result"},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    24 * time.Hour,
	}); err != nil {
		slog.Error("[NATS] Result Stream创建失败", "name", resultStream, "error", err)
	}
	client.Config.TaskStream = taskStream
	client.Config.ResultStream = resultStream

	kvBucket := config.Nats.KVBucket
	if kvBucket == "" {
		kvBucket = "MONITOR_RULES"
	}
	if kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  kvBucket,
		History: 1,
	}); err != nil {
		slog.Error("[NATS] KV初始化失败", "bucket", kvBucket, "error", err)
	} else {
		client.KV = kv
	}

	objBucket := config.Nats.ObjBucket
	if objBucket == "" {
		objBucket = "MONITOR_OBJECTS"
	}
	if objStore, err := js.CreateOrUpdateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket:   objBucket,
		MaxBytes: 1 << 30,
	}); err != nil {
		slog.Error("[NATS] Object Store初始化失败", "bucket", objBucket, "error", err)
	} else {
		client.ObjStore = objStore
	}

	return client
}

func buildNatsTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("读取CA证书失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("CA证书解析失败")
		}
		tlsCfg.RootCAs = pool
	}
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("加载客户端证书失败: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func (c *NatsClient) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}

func (c *NatsClient) IsConnected() bool {
	return c.Conn != nil && c.Conn.IsConnected()
}
