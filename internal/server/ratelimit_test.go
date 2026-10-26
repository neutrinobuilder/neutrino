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

package server_test

import (
	"testing"
	"time"

	serverhs "neutrino/internal/server"
)

func TestRateLimiterAllowsUnderMax(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 3)
	for i := range 3 {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("attempt %d: want allowed", i+1)
		}
	}
}

func TestRateLimiterBlocksOverMax(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 3)
	for range 3 {
		rl.Allow("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("RateLimiter: attempt beyond the allowed maximum")
	}
}

func TestRateLimiterPerIPIsolation(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 1)
	if !rl.Allow("1.1.1.1") {
		t.Fatal("first IP: want allowed")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("second IP: must not share the first one's budget")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatal("first IP: the second attempt should have been blocked")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := serverhs.NewRateLimiter(30*time.Millisecond, 1)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("first attempt: want allowed")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("second attempt within the window: want blocked")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("after the window expires: want allowed")
	}
}

func TestRateLimiterCleanupRemovesStale(t *testing.T) {
	rl := serverhs.NewRateLimiter(20*time.Millisecond, 1)
	rl.Allow("1.2.3.4")
	time.Sleep(40 * time.Millisecond)
	rl.Cleanup()
	if !rl.Allow("1.2.3.4") {
		t.Fatal("after Cleanup of an expired history: want allowed")
	}
}

func TestAllowRequestLoopbackAlwaysAllowed(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 1)
	for i := range 5 {
		if !rl.AllowRequest("127.0.0.1:12345") {
			t.Fatalf("loopback request %d: want always allowed", i+1)
		}
	}
}

// TestAllowRequestMalformedAddrDenied verifies that an unparsable remoteAddr
// (SplitHostPort failing) is denied (fail-closed), never treated as an
// "empty IP", which AllowRequest always allows, silently bypassing the
// rate limit for any malformed input.
func TestAllowRequestMalformedAddrDenied(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 1)
	if rl.AllowRequest("address-without-port") {
		t.Fatal("AllowRequest: an unparseable remoteAddr (SplitHostPort fails) must be denied, not allowed")
	}
}

func TestAllowRequestNonLoopbackRespectsLimit(t *testing.T) {
	rl := serverhs.NewRateLimiter(time.Minute, 1)
	if !rl.AllowRequest("203.0.113.1:9999") {
		t.Fatal("first non-loopback attempt: want allowed")
	}
	if rl.AllowRequest("203.0.113.1:9999") {
		t.Fatal("second non-loopback attempt: want blocked")
	}
}
