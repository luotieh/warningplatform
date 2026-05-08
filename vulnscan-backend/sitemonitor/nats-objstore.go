package sitemonitor

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/nats-io/nats.go/jetstream"
)

type objStoreWrapper struct {
	store jetstream.ObjectStore
}

func (w *objStoreWrapper) PutGzip(ctx context.Context, key string, data []byte) error {
	if w == nil || w.store == nil {
		return fmt.Errorf("Object Store 未初始化")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	_, err := w.store.PutBytes(ctx, key, buf.Bytes())
	if err != nil {
		return fmt.Errorf("object store put: %w", err)
	}
	slog.Debug("[ObjStore] put gzip", "key", key, "raw", len(data), "compressed", buf.Len())
	return nil
}

func (w *objStoreWrapper) GetGzip(ctx context.Context, key string) ([]byte, error) {
	if w == nil || w.store == nil {
		return nil, fmt.Errorf("Object Store 未初始化")
	}
	result, err := w.store.GetBytes(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("object store get: %w", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(result))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	const maxDecompressSize = 256 << 20
	data, err := io.ReadAll(io.LimitReader(gz, maxDecompressSize+1))
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	if len(data) > maxDecompressSize {
		return nil, fmt.Errorf("gzip 解压后数据超过大小限制 (%d bytes)", maxDecompressSize)
	}
	return data, nil
}

func (w *objStoreWrapper) PutRaw(ctx context.Context, key string, data []byte) error {
	if w == nil || w.store == nil {
		return fmt.Errorf("Object Store 未初始化")
	}
	_, err := w.store.PutBytes(ctx, key, data)
	if err != nil {
		return fmt.Errorf("object store put: %w", err)
	}
	slog.Debug("[ObjStore] put raw", "key", key, "size", len(data))
	return nil
}

func (w *objStoreWrapper) GetRaw(ctx context.Context, key string) ([]byte, error) {
	if w == nil || w.store == nil {
		return nil, fmt.Errorf("Object Store 未初始化")
	}
	data, err := w.store.GetBytes(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("object store get: %w", err)
	}
	return data, nil
}

func (w *objStoreWrapper) Delete(ctx context.Context, key string) error {
	if w == nil || w.store == nil {
		return fmt.Errorf("Object Store 未初始化")
	}
	return w.store.Delete(ctx, key)
}

func (w *objStoreWrapper) DeleteSilent(ctx context.Context, key string) {
	if w == nil || w.store == nil {
		return
	}
	if err := w.store.Delete(ctx, key); err != nil {
		slog.Debug("[ObjStore] delete skipped", "key", key, "error", err)
	}
}
