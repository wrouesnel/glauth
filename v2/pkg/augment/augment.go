// Package augment adds attributes to the entries the ldap backend forwards
// from the directory it proxies, as a site's own fields beside Active
// Directory's. The directory still decides who exists and who may bind;
// augmenters only add to what it answers.
//
// An augmenter registers itself by name from init(), and a backend names the
// augmenters it runs, in order:
//
//	[[backends]]
//	  datastore = "ldap"
//	  augment = ["example"]
package augment

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

// Request is a search the ldap backend has forwarded, with what the directory
// answered.
type Request struct {
	// BoundDN is who searched, as they bound.
	BoundDN string
	// Search is the search as the client made it.
	Search ldap.SearchRequest
	// Entries are the directory's answers, which the augmenter may add to. They
	// have only the attributes the client asked for: an augmenter which needs
	// others finds the entry by its DN.
	Entries []*ldap.Entry
}

// Wants reports whether the client asked for an attribute: by name, or by
// asking for all user attributes (none named, or "*").
func (r *Request) Wants(attribute string) bool {
	if len(r.Search.Attributes) == 0 {
		return true
	}
	for _, a := range r.Search.Attributes {
		if a == "*" || strings.EqualFold(a, attribute) {
			return true
		}
	}
	return false
}

// Augmenter adds attributes to a forwarded search's entries.
type Augmenter interface {
	Augment(ctx context.Context, req *Request) error
}

// Factory makes an augmenter for a backend.
type Factory func(backend config.Backend) (Augmenter, error)

var (
	mu        sync.Mutex
	factories = map[string]Factory{}
)

// Register makes an augmenter available by name.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := factories[name]; dup {
		panic("augment: " + name + " is registered twice")
	}
	factories[name] = f
}

// Names lists the registered augmenters.
func Names() []string {
	mu.Lock()
	defer mu.Unlock()
	names := make([]string, 0, len(factories))
	for n := range factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Chain is a backend's augmenters, run in order.
type Chain []Augmenter

// New makes the augmenters a backend names.
func New(backend config.Backend) (Chain, error) {
	var chain Chain
	for _, name := range backend.Augment {
		mu.Lock()
		f, ok := factories[name]
		mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("augment: no augmenter %q (there are: %s)", name, strings.Join(Names(), ", "))
		}
		a, err := f(backend)
		if err != nil {
			return nil, fmt.Errorf("augment: %s: %w", name, err)
		}
		chain = append(chain, a)
	}
	return chain, nil
}

// Augment runs each augmenter in turn, stopping at the first which fails.
func (c Chain) Augment(ctx context.Context, req *Request) error {
	for _, a := range c {
		if err := a.Augment(ctx, req); err != nil {
			return err
		}
	}
	return nil
}
