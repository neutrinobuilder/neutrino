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
	"testing"
	"time"

	"neutrino/internal/shared"
)

// TestRoomRegistryCleanupStaleSessions verifies that CleanupStaleSessions
// reaches the sessions of EVERY registered room, not just one, leaving
// fresh ones untouched. Internal package (not server_test): roomState and
// its sessions field aren't reachable from RoomRegistry's public API alone.
func TestRoomRegistryCleanupStaleSessions(t *testing.T) {
	reg := NewRoomRegistry()
	r1 := reg.GetOrCreateRoom("room-1")
	r2 := reg.GetOrCreateRoom("room-2")

	r1.sessions.Add(&UserSession{UserID: "fresh-1", LastSeen: time.Now().UTC()})
	r1.sessions.Add(&UserSession{UserID: "stale-1", LastSeen: time.Now().UTC().Add(-time.Hour)})
	r2.sessions.Add(&UserSession{UserID: "stale-2", LastSeen: time.Now().UTC().Add(-time.Hour)})

	removed := reg.CleanupStaleSessions(10 * time.Minute)
	if removed != 2 {
		t.Fatalf("CleanupStaleSessions: want 2 removed in total, got %d", removed)
	}
	if _, ok := r1.sessions.Get("fresh-1"); !ok {
		t.Fatal("CleanupStaleSessions: fresh session wrongly removed")
	}
	if _, ok := r1.sessions.Get("stale-1"); ok {
		t.Fatal("CleanupStaleSessions: stale session still present in room 1")
	}
	if _, ok := r2.sessions.Get("stale-2"); ok {
		t.Fatal("CleanupStaleSessions: stale session still present in room 2")
	}
}

// TestRoomRegistryRemoveSecretEvictsEmptyRoom verifies that removing the
// LAST valid secret of a room (no connection ever happened, state still
// nil) makes the entry disappear from the registry entirely, otherwise it
// stays in RAM for the rest of the process's life, with no way left to
// authenticate against it.
func TestRoomRegistryRemoveSecretEvictsEmptyRoom(t *testing.T) {
	reg := NewRoomRegistry()
	secret := []byte("s1")
	reg.AddSecret("room-1", secret, "alice", nil, nil, nil)

	reg.mu.RLock()
	_, exists := reg.rooms["room-1"]
	reg.mu.RUnlock()
	if !exists {
		t.Fatal("AddSecret: want the entry present")
	}

	reg.RemoveSecret("room-1", secret)

	reg.mu.RLock()
	_, stillExists := reg.rooms["room-1"]
	reg.mu.RUnlock()
	if stillExists {
		t.Fatal("RemoveSecret: entry still present after removing the last secret")
	}
}

// TestRoomRegistryReleaseRoomIfEmptyKeepsSecretsClearsState verifies that
// when the last CONNECTED MEMBER leaves but the room still has valid
// secrets (no ban, just a disconnection), the entry stays in the registry
// a future member must still be able to authenticate with the same
// secret, but the runtime state (hub+sessions) gets zeroed and lazily
// recreated by GetOrCreateRoom, not left alive forever while empty.
func TestRoomRegistryReleaseRoomIfEmptyKeepsSecretsClearsState(t *testing.T) {
	reg := NewRoomRegistry()
	secret := []byte("s1")
	reg.AddSecret("room-1", secret, "alice", nil, nil, nil)

	rs1 := reg.GetOrCreateRoom("room-1")
	// nil is a valid *websocket.Conn here: writeLoop only touches it on the
	// first Write, never reached because no data to write arrives before
	// Unregister below.
	rs1.hub.Register("u1", nil)
	if rs1.hub.ConnCount() != 1 {
		t.Fatalf("ConnCount: want 1, got %d", rs1.hub.ConnCount())
	}

	// Connection still active: ReleaseRoomIfEmpty must not touch anything.
	reg.ReleaseRoomIfEmpty("room-1")
	reg.mu.RLock()
	e := reg.rooms["room-1"]
	reg.mu.RUnlock()
	if e == nil || e.state == nil {
		t.Fatal("ReleaseRoomIfEmpty released the state with a connection still active")
	}

	rs1.hub.Unregister("u1")
	if rs1.hub.ConnCount() != 0 {
		t.Fatalf("ConnCount after Unregister: want 0, got %d", rs1.hub.ConnCount())
	}

	reg.ReleaseRoomIfEmpty("room-1")
	reg.mu.RLock()
	e = reg.rooms["room-1"]
	reg.mu.RUnlock()
	if e == nil {
		t.Fatal("ReleaseRoomIfEmpty removed the entry while it still had a valid secret")
	}
	if e.state != nil {
		t.Fatal("ReleaseRoomIfEmpty didn't reset the runtime state with zero connections")
	}

	// The secret stays valid: LookupSecret must still find it.
	nonce, _ := shared.RandomBytes(32)
	roomKey, err := shared.DeriveContactRoomKey(secret, shared.CurrentPeriod())
	if err != nil {
		t.Fatal(err)
	}
	proof := shared.ComputeRoomProof(roomKey, nonce)
	if _, roomID, _, _, _, _, _, ok := reg.LookupSecret(nonce, proof); !ok || roomID != "room-1" {
		t.Fatalf("LookupSecret after releasing the state: ok=%v roomID=%q, want a match on room-1", ok, roomID)
	}

	// GetOrCreateRoom must recreate a new state, not resurrect the old one.
	rs2 := reg.GetOrCreateRoom("room-1")
	if rs2 == rs1 {
		t.Fatal("GetOrCreateRoom returned the old state instead of recreating a new one")
	}
}

// TestClaimIdentitySlotRejectsDifferentDevice reproduces the central case
// of "one device per identity per room": a DIFFERENT device of the same
// identityPub must never be able to claim the already-occupied slot,
// ok=false, no evictUserID (nobody gets disconnected, the existing session
// stays intact).
func TestClaimIdentitySlotRejectsDifferentDevice(t *testing.T) {
	reg := NewRoomRegistry()
	rs := reg.GetOrCreateRoom("room-1")
	identityPub := []byte("identity-pub-32-bytes-long-value")
	devA := []byte("device-A-pub")
	devB := []byte("device-B-pub")

	evict, ok := rs.ClaimIdentitySlot(identityPub, devA, "user-A")
	if !ok || evict != "" {
		t.Fatalf("first claim: want ok=true evict=\"\", got ok=%v evict=%q", ok, evict)
	}

	evict, ok = rs.ClaimIdentitySlot(identityPub, devB, "user-B")
	if ok {
		t.Fatal("a DIFFERENT device of the same identity must not be able to claim the occupied slot")
	}
	if evict != "" {
		t.Errorf("a refused claim must never report an evictUserID, got %q", evict)
	}
}

// TestClaimIdentitySlotAllowsSameDeviceReconnectAndEvicts verifies that the
// SAME device (same devicePub) can reclaim the slot again with a new
// session user_id (a genuine reconnection), evictUserID must report the
// previous session, to be explicitly closed by the caller (Hub.conns is
// keyed by user_id, a new user_id doesn't replace the old one on its own).
func TestClaimIdentitySlotAllowsSameDeviceReconnectAndEvicts(t *testing.T) {
	reg := NewRoomRegistry()
	rs := reg.GetOrCreateRoom("room-1")
	identityPub := []byte("identity-pub-32-bytes-long-value")
	dev := []byte("device-A-pub")

	evict, ok := rs.ClaimIdentitySlot(identityPub, dev, "user-1")
	if !ok || evict != "" {
		t.Fatalf("first claim: want ok=true evict=\"\", got ok=%v evict=%q", ok, evict)
	}

	evict, ok = rs.ClaimIdentitySlot(identityPub, dev, "user-2")
	if !ok {
		t.Fatal("the SAME device must be able to reclaim its own slot (reconnection)")
	}
	if evict != "user-1" {
		t.Errorf("evictUserID: want %q (the previous session to close), got %q", "user-1", evict)
	}
}

// TestClaimIdentitySlotIndependentIdentities verifies that two DIFFERENT
// identities never contend for the same slot, each claims and keeps its
// own independently of the other.
func TestClaimIdentitySlotIndependentIdentities(t *testing.T) {
	reg := NewRoomRegistry()
	rs := reg.GetOrCreateRoom("room-1")
	identityA := []byte("identity-A-32-bytes-long-value!")
	identityB := []byte("identity-B-32-bytes-long-value!")

	if _, ok := rs.ClaimIdentitySlot(identityA, []byte("devA"), "user-A"); !ok {
		t.Fatal("claim identity A: want ok=true")
	}
	if _, ok := rs.ClaimIdentitySlot(identityB, []byte("devB"), "user-B"); !ok {
		t.Fatal("claim identity B (different from A): want ok=true, must not be blocked by A")
	}
	// A tries again with a different device: must remain blocked ONLY by
	// itself, never by B.
	if _, ok := rs.ClaimIdentitySlot(identityA, []byte("devA-other"), "user-A2"); ok {
		t.Fatal("a second device of A must stay refused regardless of B's slot")
	}
}

// TestReleaseIdentitySlotOnlyIfCurrentOwner verifies that releasing a slot
// NEVER erases a more recent entry, if the same device has already
// reconnected (ClaimIdentitySlot with a new user_id, which replaces the
// entry), the OLD session's disconnection defer must not free the slot
// just occupied by the NEW one.
func TestReleaseIdentitySlotOnlyIfCurrentOwner(t *testing.T) {
	reg := NewRoomRegistry()
	rs := reg.GetOrCreateRoom("room-1")
	identityPub := []byte("identity-pub-32-bytes-long-value")
	dev := []byte("device-A-pub")

	rs.ClaimIdentitySlot(identityPub, dev, "user-1")
	rs.ClaimIdentitySlot(identityPub, dev, "user-2") // reconnection: replaces user-1

	// "Late" release of the old session (user-1, by now replaced): must not
	// touch user-2's slot.
	rs.ReleaseIdentitySlot(identityPub, "user-1")
	if _, ok := rs.ClaimIdentitySlot(identityPub, []byte("device-B-pub"), "user-3"); ok {
		t.Fatal("the late release of an already-replaced session wrongly freed the slot held by user-2")
	}

	// Release of the CURRENT session (user-2): this one does free the slot.
	rs.ReleaseIdentitySlot(identityPub, "user-2")
	if _, ok := rs.ClaimIdentitySlot(identityPub, []byte("device-B-pub"), "user-3"); !ok {
		t.Fatal("releasing the current session should have freed the slot for a different device")
	}
}

// TestClaimIdentitySlotEmptyIdentityNeverBlocks verifies that an empty
// identityPub (should never happen for a real member, but missing
// data must never block a connection) never applies enforcement, always
// ok, regardless of how many times claimed.
func TestClaimIdentitySlotEmptyIdentityNeverBlocks(t *testing.T) {
	reg := NewRoomRegistry()
	rs := reg.GetOrCreateRoom("room-1")
	for i, userID := range []string{"user-1", "user-2", "user-3"} {
		if _, ok := rs.ClaimIdentitySlot(nil, []byte("dev"), userID); !ok {
			t.Fatalf("claim #%d with an empty identityPub: want ok=true always", i)
		}
	}
}
