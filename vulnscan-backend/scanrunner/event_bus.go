package scanrunner

import (
	"encoding/json"
	"sync"
	"time"

	"vulnscan-backend/model"
)

type EventType string

const (
	EventFinding  EventType = "finding"
	EventProgress EventType = "progress"
	EventStage    EventType = "stage"
	EventDone     EventType = "done"
	EventLog      EventType = "log"
)

type ScanEvent struct {
	Type    EventType       `json:"type"`
	TaskID  string          `json:"task_id"`
	Payload json.RawMessage `json:"payload"`
	Time    time.Time       `json:"time"`
}

type FindingPayload struct {
	Findings []model.ScanFinding `json:"findings"`
	Stage    string              `json:"stage"`
	Module   string              `json:"module"`
}

type ProgressPayload struct {
	TaskProgress
}

type StagePayload struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
}

type DonePayload struct {
	Status   string `json:"status"`
	ErrorMsg string `json:"error_msg,omitempty"`
}

type LogPayload struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	Stage   string `json:"stage,omitempty"`
	Module  string `json:"module,omitempty"`
}

type subscriber struct {
	ch     chan ScanEvent
	taskID string
}

type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]*subscriber
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string][]*subscriber),
	}
}

func (eb *EventBus) Subscribe(taskID string, bufSize int) <-chan ScanEvent {
	if bufSize <= 0 {
		bufSize = 256
	}
	sub := &subscriber{
		ch:     make(chan ScanEvent, bufSize),
		taskID: taskID,
	}

	eb.mu.Lock()
	eb.subscribers[taskID] = append(eb.subscribers[taskID], sub)
	eb.mu.Unlock()

	return sub.ch
}

func (eb *EventBus) Unsubscribe(taskID string, ch <-chan ScanEvent) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subs := eb.subscribers[taskID]
	for i, sub := range subs {
		if sub.ch == ch {
			close(sub.ch)
			eb.subscribers[taskID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	if len(eb.subscribers[taskID]) == 0 {
		delete(eb.subscribers, taskID)
	}
}

func (eb *EventBus) Publish(taskID string, evt ScanEvent) {
	eb.mu.RLock()
	subs := eb.subscribers[taskID]
	eb.mu.RUnlock()

	for _, sub := range subs {
		select {
		case sub.ch <- evt:
		default:
			// subscriber too slow, drop oldest and retry
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- evt:
			default:
			}
		}
	}
}

func (eb *EventBus) CloseTask(taskID string) {
	eb.mu.Lock()
	subs := eb.subscribers[taskID]
	delete(eb.subscribers, taskID)
	eb.mu.Unlock()

	for _, sub := range subs {
		close(sub.ch)
	}
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func NewFindingEvent(taskID string, findings []model.ScanFinding, stage, module string) ScanEvent {
	return ScanEvent{
		Type:   EventFinding,
		TaskID: taskID,
		Payload: mustJSON(FindingPayload{
			Findings: findings,
			Stage:    stage,
			Module:   module,
		}),
		Time: time.Now(),
	}
}

func NewProgressEvent(taskID string, p TaskProgress) ScanEvent {
	return ScanEvent{
		Type:    EventProgress,
		TaskID:  taskID,
		Payload: mustJSON(ProgressPayload{p}),
		Time:    time.Now(),
	}
}

func NewStageEvent(taskID, stage, status string) ScanEvent {
	return ScanEvent{
		Type:    EventStage,
		TaskID:  taskID,
		Payload: mustJSON(StagePayload{Stage: stage, Status: status}),
		Time:    time.Now(),
	}
}

func NewDoneEvent(taskID, status, errMsg string) ScanEvent {
	return ScanEvent{
		Type:    EventDone,
		TaskID:  taskID,
		Payload: mustJSON(DonePayload{Status: status, ErrorMsg: errMsg}),
		Time:    time.Now(),
	}
}

func NewLogEvent(taskID, level, message, stage, module string) ScanEvent {
	return ScanEvent{
		Type:   EventLog,
		TaskID: taskID,
		Payload: mustJSON(LogPayload{
			Level:   level,
			Message: message,
			Stage:   stage,
			Module:  module,
		}),
		Time: time.Now(),
	}
}
