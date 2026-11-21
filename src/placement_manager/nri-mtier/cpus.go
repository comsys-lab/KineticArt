package main

import (
	"strings"
	"sync"
)

type cpuPool struct {
	mu   sync.Mutex
	cpus []string
	cnt  map[string]int
	byID map[string]string
}

func newCPUPool(list string) *cpuPool {
	p := &cpuPool{cnt: map[string]int{}, byID: map[string]string{}}
	for _, c := range strings.Split(list, ",") {
		if c = strings.TrimSpace(c); c != "" {
			p.cpus = append(p.cpus, c)
		}
	}
	return p
}

func (p *cpuPool) enabled() bool { return len(p.cpus) > 0 }

func (p *cpuPool) pick(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.byID[id]; ok {
		return c
	}
	best := p.cpus[0]
	for _, c := range p.cpus[1:] {
		if p.cnt[c] < p.cnt[best] {
			best = c
		}
	}
	p.cnt[best]++
	p.byID[id] = best
	return best
}

func (p *cpuPool) adopt(id, cpus string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.byID[id]; ok {
		return false
	}
	for _, c := range p.cpus {
		if c == strings.TrimSpace(cpus) {
			p.cnt[c]++
			p.byID[id] = c
			return true
		}
	}
	return false
}

func (p *cpuPool) release(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.byID[id]; ok {
		p.cnt[c]--
		delete(p.byID, id)
	}
}
