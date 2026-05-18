package model

import "fmt"

type Transition[S comparable] struct {
	From  S
	To    S
	Event string
}

type StateMachine[S comparable] struct {
	name        string
	transitions map[S]map[string]S
}

func NewStateMachine[S comparable](name string, defs []Transition[S]) *StateMachine[S] {
	sm := &StateMachine[S]{name: name, transitions: make(map[S]map[string]S)}
	for _, t := range defs {
		if sm.transitions[t.From] == nil {
			sm.transitions[t.From] = make(map[string]S)
		}
		sm.transitions[t.From][t.Event] = t.To
	}
	return sm
}

func (sm *StateMachine[S]) Can(current S, event string) bool {
	events, ok := sm.transitions[current]
	if !ok {
		return false
	}
	_, ok = events[event]
	return ok
}

func (sm *StateMachine[S]) Apply(current S, event string) (S, error) {
	events, ok := sm.transitions[current]
	if !ok {
		var zero S
		return zero, fmt.Errorf("[%s] 状态 %v 无可用转换", sm.name, current)
	}
	next, ok := events[event]
	if !ok {
		var zero S
		return zero, fmt.Errorf("[%s] 状态 %v 不允许操作 %s", sm.name, current, event)
	}
	return next, nil
}

func (sm *StateMachine[S]) AllowedEvents(current S) []string {
	events, ok := sm.transitions[current]
	if !ok {
		return nil
	}
	result := make([]string, 0, len(events))
	for e := range events {
		result = append(result, e)
	}
	return result
}
