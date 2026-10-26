// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package server

import (
	"net"
	"sync"
	"time"
)

// RateLimiter tracks attempts per IP within a sliding time window.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	max      int
}

func NewRateLimiter(window time.Duration, max int) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		window:   window,
		max:      max,
	}
}

// Allow returns true if the IP may proceed, false if the limit is exceeded.
func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	prev := r.attempts[ip]
	valid := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.max {
		r.attempts[ip] = valid
		return false
	}
	r.attempts[ip] = append(valid, now)
	return true
}

// AllowRequest extracts the IP from remoteAddr (r.RemoteAddr's "host:port"
// format) and calls Allow. Loopback addresses are always allowed: in Tor
// mode the daemon connects over loopback and rate-limiting 127.0.0.1 would
// block all Tor clients indiscriminately.
func (r *RateLimiter) AllowRequest(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// malformed remoteAddr (SplitHostPort failed): fail-closed, not
		// fail-open, a rate limiter must deny by default on unexpected
		// input, never silently bypass the limit. Likely unreachable with
		// standard net/http (r.RemoteAddr is always a valid "host:port"
		// there), defense in depth.
		return false
	}
	if ip == "" {
		return true
	}
	if parsed := net.ParseIP(ip); parsed == nil || parsed.IsLoopback() {
		return true
	}
	return r.Allow(ip)
}

// Cleanup removes IPs with no recent attempts (call periodically).
func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-r.window)
	for ip, times := range r.attempts {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(r.attempts, ip)
		} else {
			r.attempts[ip] = valid
		}
	}
}
