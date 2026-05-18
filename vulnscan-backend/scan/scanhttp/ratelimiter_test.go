package scanhttp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTokenBucketWaitCancel(t *testing.T) {
	tb := NewTokenBucket(0.01, 0.01)
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- tb.Wait(ctx)
		}()
	}

	time.Sleep(30 * time.Millisecond)
	cancel()
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestTokenBucketWaitTakesToken(t *testing.T) {
	tb := NewTokenBucket(1000, 10)
	ctx := context.Background()
	if err := tb.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTokenBucketConcurrentWaitNoPanic(t *testing.T) {
	tb := NewTokenBucket(500, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tb.Wait(ctx)
		}()
	}
	wg.Wait()
}
