package realtime

import "sync/atomic"

// Publisher is intentionally small so business code does not depend on a
// concrete Socket.IO implementation. The socketio.Hub implements this method.
type Publisher interface {
	Broadcast(room, event string, data any)
}

var current atomic.Value // stores Publisher

func Register(p Publisher) {
	if p != nil {
		current.Store(p)
	}
}

func Get() Publisher {
	v := current.Load()
	if v == nil {
		return nil
	}
	p, _ := v.(Publisher)
	return p
}

func Broadcast(room, event string, data any) {
	if room == "" || event == "" {
		return
	}
	if p := Get(); p != nil {
		p.Broadcast(room, event, data)
	}
}

// EventListRoom 是事件列表页订阅的全局房间：分析完成/失败等影响列表行的
// 状态变化在按事件房间广播之外同步广播到该房间，列表页据此自动刷新。
const EventListRoom = "events"

// BroadcastEventListUpdate 向事件列表房间广播行级状态变化（分析完成/失败等）。
func BroadcastEventListUpdate(payload any) {
	Broadcast(EventListRoom, "event_list_update", payload)
}

// BroadcastMessage emits a DeepSOC-compatible Socket.IO `new_message` event.
// The payload is intentionally the saved message object itself rather than a
// nested wrapper, matching the original chat frontend's expectations.
func BroadcastMessage(eventID string, message any) {
	Broadcast(eventID, "new_message", message)
}

func BroadcastExecutionUpdate(eventID string, payload any) {
	Broadcast(eventID, "execution_update", payload)
}

func BroadcastStatus(eventID string, payload any) {
	Broadcast(eventID, "status", payload)
}
