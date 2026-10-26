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

package tui

import (
	"crypto/ed25519"
	"sync"
	"testing"
)

// TestRemoteNukeFanOutCleanupDoesNotEvictNewerRetry verifies that the
// deferred cleanup of an older fan-out must not remove from the map the
// entry of a more recent retry for the same DeviceID — if it did, a
// remote_nuke_ack received afterward (stopRemoteNukeFanOut) would no longer
// find the still-ongoing retry and would fail to stop it.
//
// dialTor stays nil: every per-target goroutine of cmdRemoteNukeFanOut
// returns right away (`if dial == nil ... { return }`), so the returned
// tea.Cmd can be invoked SYNCHRONOUSLY in the test with no real network
// I/O — allowing deterministic control over the order "register A, register
// B (replacing A), run A's cleanup" without depending on the scheduler.
func TestRemoteNukeFanOutCleanupDoesNotEvictNewerRetry(t *testing.T) {
	m := &model{
		remoteNukeCancels: make(map[string]*remoteNukeEntry),
		remoteNukeMu:      &sync.Mutex{},
		signRemoteNuke: func(targetDeviceID []byte, ts string) []byte {
			return []byte("sig")
		},
	}
	targetPub := make(ed25519.PublicKey, 32)
	rec := DeviceRecordInfo{
		DeviceID: []byte{1, 2, 3, 4},
		SiblingIdentities: []DeviceIdentityRef{
			{Username: "target", IdentityPub: targetPub},
		},
	}

	cmdA := m.cmdRemoteNukeFanOut(rec)
	if cmdA == nil {
		t.Fatal("cmdRemoteNukeFanOut: want a non-nil tea.Cmd (targets not empty)")
	}
	key := "01020304"
	entryA := m.remoteNukeCancels[key]
	if entryA == nil {
		t.Fatal("cmdRemoteNukeFanOut: entry not registered after the first call")
	}

	// Retry for the SAME device before A has run its own cleanup — replaces
	// entryA with entryB in the map and cancels A's context (intended
	// behavior, not what this test covers).
	cmdB := m.cmdRemoteNukeFanOut(rec)
	if cmdB == nil {
		t.Fatal("cmdRemoteNukeFanOut (retry): want a non-nil tea.Cmd")
	}
	entryB := m.remoteNukeCancels[key]
	if entryB == nil || entryB == entryA {
		t.Fatal("cmdRemoteNukeFanOut (retry): the map entry must have been replaced by a new one")
	}

	// Runs A's deferred cleanup NOW (its ctx is already canceled, so
	// wg.Wait() returns right away) — must not touch B's entry.
	cmdA()

	if got := m.remoteNukeCancels[key]; got != entryB {
		t.Fatalf("fan-out A's cleanup removed/replaced the entry of retry B still running (got=%v, want=%v)", got, entryB)
	}

	// B's cleanup, instead, must remove its own entry normally.
	cmdB()
	if got, ok := m.remoteNukeCancels[key]; ok {
		t.Fatalf("fan-out B's cleanup didn't remove its own entry: %v", got)
	}
}
