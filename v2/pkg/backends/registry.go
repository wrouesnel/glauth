// Package backends holds the registry of datastores compiled into GLAuth.
//
// Each backend package registers itself from an init function, and the binary
// selects the backends it ships by importing them (see pkg/backends/all). A
// backend is then used by naming it as the datastore of a [[backends]] entry.
package backends

import (
	"fmt"
	"sort"
	"sync"

	"github.com/glauth/glauth/v2/pkg/handler"
)

// Factory builds a handler for one configured backend.
type Factory func(opts ...handler.Option) handler.Handler

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register makes a backend available under the given datastore name. It panics
// if the name is already taken, since that can only be a programming error.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, found := registry[name]; found {
		panic(fmt.Sprintf("backends: datastore %q registered twice", name))
	}
	registry[name] = factory
}

// Lookup returns the factory for the named datastore, if one is registered.
func Lookup(name string) (Factory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	factory, found := registry[name]
	return factory, found
}

// Names returns the registered datastore names in sorted order.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
