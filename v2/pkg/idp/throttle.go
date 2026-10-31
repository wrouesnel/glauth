package idp

import (
	"strings"
	"sync"
	"time"
)

const (
	throttleFailures = 5
	throttleWindow   = 5 * time.Minute
)

// throttle slows password guessing: after throttleFailures failed sign-ins for a
// user name within throttleWindow, further attempts for it are refused until the
// window has passed. It is keyed by user name because, behind a reverse proxy, the
// client's address isn't known.
type throttle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newThrottle() *throttle {
	return &throttle{failures: map[string][]time.Time{}}
}

func (t *throttle) recent(user string, now time.Time) []time.Time {
	var kept []time.Time
	for _, at := range t.failures[user] {
		if now.Sub(at) < throttleWindow {
			kept = append(kept, at)
		}
	}
	return kept
}

// allowed reports whether a sign-in for user may be attempted now.
func (t *throttle) allowed(user string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recent(strings.ToLower(user), now)) < throttleFailures
}

func (t *throttle) failed(user string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	user = strings.ToLower(user)
	t.failures[user] = append(t.recent(user, now), now)
}

func (t *throttle) succeeded(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, strings.ToLower(user))
}

func (t *throttle) expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for user := range t.failures {
		if kept := t.recent(user, now); len(kept) > 0 {
			t.failures[user] = kept
		} else {
			delete(t.failures, user)
		}
	}
}
