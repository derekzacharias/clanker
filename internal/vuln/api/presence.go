package api

import (
	"sync"

	"github.com/bgdnvk/clanker/internal/vuln/fleet"
)

// presence tracks agents that currently hold an open claim request.
//
// "Online" must mean *reachable*, not "reported something recently": an endpoint
// that is running the watcher can accept work right now, and one that is not
// cannot be reached at all. A held request is the strongest evidence available
// without opening an inbound port on the endpoint, so presence is derived from it.
type presence struct {
	mu      sync.Mutex
	waiters map[string]map[*waiter]struct{}
}

type waiter struct {
	ch chan fleet.Task
}

func newPresence() *presence {
	return &presence{waiters: map[string]map[*waiter]struct{}{}}
}

// register opens a waiter for an agent. The caller must cancel it.
func (p *presence) register(agentID string) *waiter {
	w := &waiter{ch: make(chan fleet.Task, 1)}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.waiters[agentID] == nil {
		p.waiters[agentID] = map[*waiter]struct{}{}
	}
	p.waiters[agentID][w] = struct{}{}
	return w
}

func (p *presence) cancel(agentID string, w *waiter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if set, ok := p.waiters[agentID]; ok {
		delete(set, w)
		if len(set) == 0 {
			delete(p.waiters, agentID)
		}
	}
}

// notify hands a newly queued task to every waiting request for that agent.
// Delivery is non-blocking: the task is already persisted, so a slow or vanished
// waiter loses nothing — the next claim picks it up.
func (p *presence) notify(agentID string, task fleet.Task) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for w := range p.waiters[agentID] {
		select {
		case w.ch <- task:
		default:
		}
	}
}

// online reports whether any request is currently held for this agent.
func (p *presence) online(agentID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.waiters[agentID]) > 0
}
