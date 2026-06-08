package orchestrate

import (
	"code.yt-security.com/public/scanengine/core"

	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

type FindingStream struct {
	ch     chan *FindingBatch
	done   chan struct{}
	closed atomic.Bool
}

type FindingBatch struct {
	Stage    string
	ModuleID string
	Findings []*core.Finding
	Targets  []*core.Target
}

func NewFindingStream(bufferSize int) *FindingStream {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	return &FindingStream{
		ch:   make(chan *FindingBatch, bufferSize),
		done: make(chan struct{}),
	}
}

func (fs *FindingStream) Send(batch *FindingBatch) (sent bool) {
	if fs.closed.Load() {
		return false
	}

	// Guard against send-on-closed-channel race between closed.Load() and actual send
	defer func() {
		if r := recover(); r != nil {
			sent = false
		}
	}()

	select {
	case fs.ch <- batch:
		return true
	default:
	}

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case fs.ch <- batch:
		return true
	case <-timer.C:
		slog.Warn("[Stream] 结果缓冲区超时，丢弃批次",
			"stage", batch.Stage,
			"module", batch.ModuleID,
			"findings", len(batch.Findings),
		)
		return false
	}
}

func (fs *FindingStream) Receive(ctx context.Context) (*FindingBatch, bool) {
	select {
	case batch, ok := <-fs.ch:
		return batch, ok
	case <-ctx.Done():
		return nil, false
	}
}

func (fs *FindingStream) Close() {
	if fs.closed.CompareAndSwap(false, true) {
		close(fs.ch)
	}
}

func (fs *FindingStream) Consume(ctx context.Context, handler func(batch *FindingBatch)) {
	defer close(fs.done)
	for {
		batch, ok := fs.Receive(ctx)
		if !ok {
			return
		}
		handler(batch)
	}
}

func (fs *FindingStream) Wait() {
	<-fs.done
}
