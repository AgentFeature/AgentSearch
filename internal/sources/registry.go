package sources

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Registry preserves registration order. Searches use a snapshot, allowing
// registration without holding a lock during provider execution.
type Registry struct {
	mu      sync.RWMutex
	ordered []Source
	byName  map[string]Source
}

func NewRegistry() *Registry { return &Registry{} }
func (r *Registry) Register(s Source) error {
	if s == nil {
		return fmt.Errorf("nil source")
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return fmt.Errorf("nil source")
		}
	}
	name := s.Name()
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid source name")
	}
	if s.Type() == "" || len(Capabilities(s)) == 0 {
		return fmt.Errorf("source requires type and search capability")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byName[name]; exists {
		return fmt.Errorf("duplicate source: %s", name)
	}
	if r.byName == nil {
		r.byName = make(map[string]Source)
	}
	r.byName[name] = s
	r.ordered = append(r.ordered, s)
	return nil
}
func (r *Registry) Lookup(name string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[name]
	return s, ok
}
func (r *Registry) All() []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Source(nil), r.ordered...)
}
