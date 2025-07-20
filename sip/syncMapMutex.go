package sip

import (
	"SRGo/global"
	"maps"
	"slices"
	"sync"
)

type ValueType interface {
	String() string
	ExceedCondition() bool
}

type ConcurrentMapMutex[T ValueType] struct {
	_map map[string]T
	mu   sync.RWMutex
}

func NewConcurrentMapMutex[T ValueType](sz int) ConcurrentMapMutex[T] {
	return ConcurrentMapMutex[T]{_map: make(map[string]T, sz)}
}

func (c *ConcurrentMapMutex[T]) Store(ky string, ss T) bool {
	c.mu.Lock()
	c._map[ky] = ss
	global.Prometrics.ConSessions.Inc()
	c.mu.Unlock()
	return ss.ExceedCondition()
}

func (c *ConcurrentMapMutex[T]) Delete(ky string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c._map, ky)
	global.Prometrics.ConSessions.Dec()
}

func (c *ConcurrentMapMutex[T]) Load(ky string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c._map[ky]
	return s, ok
}

func (c *ConcurrentMapMutex[T]) Summaries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return global.Map(slices.Collect(maps.Values(c._map)), func(x T) string { return x.String() })
}

func (c *ConcurrentMapMutex[T]) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c._map)
}

func (c *ConcurrentMapMutex[T]) IsEmpty() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c._map) == 0
}
