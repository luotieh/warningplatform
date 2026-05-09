package engine

import (
	"context"
	"sync"
)

type WorkerPool struct {
	size   int
	taskCh chan func()
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func NewWorkerPool(size int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &WorkerPool{
		size:   size,
		taskCh: make(chan func(), size*4),
		ctx:    ctx,
		cancel: cancel,
	}
	p.start()
	return p
}

func (p *WorkerPool) start() {
	for i := 0; i < p.size; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-p.ctx.Done():
					return
				case task, ok := <-p.taskCh:
					if !ok {
						return
					}
					task()
				}
			}
		}()
	}
}

func (p *WorkerPool) Submit(task func()) {
	select {
	case p.taskCh <- task:
	case <-p.ctx.Done():
	}
}

func (p *WorkerPool) Shutdown() {
	p.cancel()
	close(p.taskCh)
	p.wg.Wait()
}
