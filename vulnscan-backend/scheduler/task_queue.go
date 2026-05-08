package scheduler

import (
	"container/heap"
	"sync"
	"time"

	"vulnscan-backend/model"
)

const PriorityLevels = 10

type TaskItem struct {
	Task      *model.ScanTask
	EnqueueAt time.Time
	Priority  int
}

type taskHeap struct {
	items []*TaskItem
}

func (h *taskHeap) Len() int { return len(h.items) }

func (h *taskHeap) Less(i, j int) bool {
	a, b := h.items[i], h.items[j]
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return a.EnqueueAt.Before(b.EnqueueAt)
}

func (h *taskHeap) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }

func (h *taskHeap) Push(x any) {
	h.items = append(h.items, x.(*TaskItem))
}

func (h *taskHeap) Pop() any {
	if len(h.items) == 0 {
		return nil
	}
	old := h.items
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	h.items = old[:n-1]
	return item
}

// TaskQueue is a thread-safe priority queue for scan tasks.
// Modeled after IAM's EventQueue with heap-based priority ordering.
type TaskQueue struct {
	h  taskHeap
	mu sync.Mutex
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{}
}

func (q *TaskQueue) Push(item *TaskItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	heap.Push(&q.h, item)
}

func (q *TaskQueue) Pop() *TaskItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.h.Len() == 0 {
		return nil
	}
	return heap.Pop(&q.h).(*TaskItem)
}

func (q *TaskQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.h.Len()
}

func (q *TaskQueue) Remove(taskID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, item := range q.h.items {
		if item.Task.ID == taskID {
			heap.Remove(&q.h, i)
			return true
		}
	}
	return false
}

func NewTaskItem(task *model.ScanTask) *TaskItem {
	p := task.Priority
	if p <= 0 {
		p = 5
	}
	if p > PriorityLevels {
		p = PriorityLevels
	}
	return &TaskItem{
		Task:      task,
		EnqueueAt: time.Now(),
		Priority:  p,
	}
}
