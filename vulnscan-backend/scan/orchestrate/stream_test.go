package orchestrate

import (
	"vulnscan-backend/scan/core"

	"context"
	"sync"
	"testing"
	"time"
)

func TestStream_SendReceive(t *testing.T) {
	fs := NewFindingStream(10)

	batch := &FindingBatch{
		Stage:    "recon",
		ModuleID: "subdomain",
		Findings: []*core.Finding{{Title: "test"}},
	}

	if !fs.Send(batch) {
		t.Fatal("发送不应失败")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	got, ok := fs.Receive(ctx)
	if !ok {
		t.Fatal("接收不应失败")
	}
	if got.Stage != "recon" || got.ModuleID != "subdomain" {
		t.Errorf("接收数据不匹配: %+v", got)
	}
}

func TestStream_Close(t *testing.T) {
	fs := NewFindingStream(5)
	fs.Close()

	if fs.Send(&FindingBatch{Stage: "test"}) {
		t.Error("关闭后发送应返回 false")
	}
}

func TestStream_DoubleClose(t *testing.T) {
	fs := NewFindingStream(5)
	fs.Close()
	fs.Close() // 不应 panic
}

func TestStream_ReceiveAfterClose(t *testing.T) {
	fs := NewFindingStream(5)
	fs.Send(&FindingBatch{Stage: "s1"})
	fs.Close()

	ctx := context.Background()
	got, ok := fs.Receive(ctx)
	if !ok || got.Stage != "s1" {
		t.Error("关闭后应能读取已缓冲的数据")
	}

	_, ok = fs.Receive(ctx)
	if ok {
		t.Error("缓冲区读完后应返回 false")
	}
}

func TestStream_ContextCancel(t *testing.T) {
	fs := NewFindingStream(5)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, ok := fs.Receive(ctx)
	if ok {
		t.Error("取消的 context 应返回 false")
	}
}

func TestStream_BufferFull(t *testing.T) {
	fs := NewFindingStream(2)

	fs.Send(&FindingBatch{Stage: "1"})
	fs.Send(&FindingBatch{Stage: "2"})
	ok := fs.Send(&FindingBatch{Stage: "3"})

	if ok {
		t.Error("缓冲区满时应返回 false（丢弃）")
	}
}

func TestStream_Consume(t *testing.T) {
	fs := NewFindingStream(10)
	ctx := context.Background()

	batches := []*FindingBatch{
		{Stage: "s1", ModuleID: "m1"},
		{Stage: "s2", ModuleID: "m2"},
		{Stage: "s3", ModuleID: "m3"},
	}

	for _, b := range batches {
		fs.Send(b)
	}
	fs.Close()

	var received []string
	var mu sync.Mutex

	go fs.Consume(ctx, func(batch *FindingBatch) {
		mu.Lock()
		received = append(received, batch.ModuleID)
		mu.Unlock()
	})

	fs.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 {
		t.Errorf("应消费 3 条, got %d", len(received))
	}
}
