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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// validProof computes a valid room_proof for secret in the current period,
// the same way a client would during the handshake.
func validProof(t *testing.T, secret, nonceClient []byte) []byte {
	t.Helper()
	roomKey, err := shared.DeriveContactRoomKey(secret, shared.CurrentPeriod())
	if err != nil {
		t.Fatal(err)
	}
	return shared.ComputeRoomProof(roomKey, nonceClient)
}

// staticResolver builds a resolver that always returns the same key pair —
// convenient for tests that aren't about live resolution, just the
// propagation of the value.
func staticResolver(peerKey shared.RelPeerKey, signingKey shared.RelSigningKey) func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
	return func() (shared.RelPeerKey, shared.RelSigningKey, bool) { return peerKey, signingKey, true }
}

func TestRoomRegistryAddSecretAndLookup(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	secret, _ := shared.RandomBytes(32)
	reg.AddSecret("room-1", secret, "alice", nil, nil, nil)

	nonce, _ := shared.RandomBytes(32)
	proof := validProof(t, secret, nonce)

	gotSecret, roomID, label, _, _, _, _, ok := reg.LookupSecret(nonce, proof)
	if !ok {
		t.Fatal("LookupSecret: want a match")
	}
	if roomID != "room-1" {
		t.Errorf("roomID: want %q, got %q", "room-1", roomID)
	}
	if label != "alice" {
		t.Errorf("label: want %q, got %q", "alice", label)
	}
	if string(gotSecret) != string(secret) {
		t.Error("LookupSecret: the returned secret doesn't match")
	}
}

// TestRoomRegistryLookupReturnsIdentityPub covers the propagation of the
// peer's IdentityKey-per-relationship: AddSecret/ReplaceSecret must keep
// the resolver associated with the secret, invoked by LookupSecret to
// populate HandshakeResult.MatchedIdentityPub.
func TestRoomRegistryLookupReturnsIdentityPub(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	secret, _ := shared.RandomBytes(32)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg.AddSecret("room-1", secret, "alice", nil, nil, staticResolver(shared.RelPeerKey{Pub: pub}, shared.RelSigningKey{}))

	nonce, _ := shared.RandomBytes(32)
	_, _, _, _, _, gotPeerKey, _, ok := reg.LookupSecret(nonce, validProof(t, secret, nonce))
	if !ok {
		t.Fatal("LookupSecret: want a match")
	}
	if !bytes.Equal(gotPeerKey.Pub, pub) {
		t.Errorf("identityPub doesn't match: want %x, got %x", pub, gotPeerKey.Pub)
	}

	// ReplaceSecret with a new identityPub: the old secret stops
	// authenticating, the new one carries the new pubkey.
	newSecret, _ := shared.RandomBytes(32)
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg.ReplaceSecret("room-1", secret, newSecret, "alice", nil, nil, staticResolver(shared.RelPeerKey{Pub: newPub}, shared.RelSigningKey{}))
	_, _, _, _, _, gotNewPeerKey, _, ok := reg.LookupSecret(nonce, validProof(t, newSecret, nonce))
	if !ok {
		t.Fatal("LookupSecret after ReplaceSecret: want a match")
	}
	if !bytes.Equal(gotNewPeerKey.Pub, newPub) {
		t.Errorf("identityPub after ReplaceSecret doesn't match: want %x, got %x", newPub, gotNewPeerKey.Pub)
	}
}

// TestRoomRegistryResolvesKeysLive verifies the structural property that
// prevents stale-signature handshake failures between contacts whose
// relationship was re-established: the secret registers a RESOLVER, not a
// key pair — a rotation of the IdentityKey-per-relationship AFTER the
// secret is already registered is reflected immediately on the next
// LookupSecret, with no separate refresh call needed.
func TestRoomRegistryResolvesKeysLive(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	secret, _ := shared.RandomBytes(32)
	identityPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, oldSigningPriv, _ := ed25519.GenerateKey(rand.Reader)

	// current* is mutated "in the background" (simulates a relationship
	// rotation, e.g. keystore.Contact.RelIdentityPriv updated) — the
	// resolver reads it again on every call, never just once.
	current := struct {
		peerPub     ed25519.PublicKey
		signingPriv ed25519.PrivateKey
	}{peerPub: oldPeerPub, signingPriv: oldSigningPriv}
	resolve := func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
		return shared.RelPeerKey{Pub: current.peerPub}, shared.RelSigningKey{Priv: current.signingPriv}, true
	}
	reg.AddSecret("room-1", secret, "alice", identityPub, devicePub, resolve)

	nonce, _ := shared.RandomBytes(32)
	_, _, _, _, _, gotPeerKey, gotSigningKey, ok := reg.LookupSecret(nonce, validProof(t, secret, nonce))
	if !ok {
		t.Fatal("LookupSecret: want a match")
	}
	if !bytes.Equal(gotPeerKey.Pub, oldPeerPub) || !bytes.Equal(gotSigningKey.Priv, oldSigningPriv) {
		t.Fatal("LookupSecret: want the initial key pair")
	}

	// The "rotation": no call to RoomRegistry, only the source the
	// resolver is hooked to changes.
	newPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, newSigningPriv, _ := ed25519.GenerateKey(rand.Reader)
	current.peerPub = newPeerPub
	current.signingPriv = newSigningPriv

	_, _, _, _, _, gotPeerKey2, gotSigningKey2, ok := reg.LookupSecret(nonce, validProof(t, secret, nonce))
	if !ok {
		t.Fatal("LookupSecret after the rotation: want a match (the secret doesn't change)")
	}
	if !bytes.Equal(gotPeerKey2.Pub, newPeerPub) {
		t.Errorf("peerKey not resolved live: want %x, got %x", newPeerPub, gotPeerKey2.Pub)
	}
	if !bytes.Equal(gotSigningKey2.Priv, newSigningPriv) {
		t.Errorf("mySigningKey not resolved live: want %x, got %x", newSigningPriv, gotSigningKey2.Priv)
	}
}

// TestRoomRegistryResolveKeysScopedPerDevice verifies that a contact with
// two known devices invited into the SAME room has two memberSecret
// entries with the same identityPub but different devicePub and SO two
// independent resolvers — a relationship rotation on ONE of the two must
// never be reflected on the other, which stays valid with its own keys.
func TestRoomRegistryResolveKeysScopedPerDevice(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	identityPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceAPub, _, _ := ed25519.GenerateKey(rand.Reader)
	deviceBPub, _, _ := ed25519.GenerateKey(rand.Reader)

	secretA, _ := shared.RandomBytes(32)
	peerAPub, _, _ := ed25519.GenerateKey(rand.Reader)
	currentAPub := peerAPub
	reg.AddSecret("room-1", secretA, "bob", identityPub, deviceAPub, func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
		return shared.RelPeerKey{Pub: currentAPub}, shared.RelSigningKey{}, true
	})

	secretB, _ := shared.RandomBytes(32)
	peerBPub, _, _ := ed25519.GenerateKey(rand.Reader)
	reg.AddSecret("room-1", secretB, "bob", identityPub, deviceBPub, staticResolver(shared.RelPeerKey{Pub: peerBPub}, shared.RelSigningKey{}))

	// Rotation on device A only: only A's resolver changes result.
	newPeerAPub, _, _ := ed25519.GenerateKey(rand.Reader)
	currentAPub = newPeerAPub

	nonce, _ := shared.RandomBytes(32)
	_, _, _, _, _, gotA, _, okA := reg.LookupSecret(nonce, validProof(t, secretA, nonce))
	if !okA || !bytes.Equal(gotA.Pub, newPeerAPub) {
		t.Errorf("device A: peerKey not updated by its own resolver, want %x", newPeerAPub)
	}
	_, _, _, _, _, gotB, _, okB := reg.LookupSecret(nonce, validProof(t, secretB, nonce))
	if !okB || !bytes.Equal(gotB.Pub, peerBPub) {
		t.Errorf("device B: peerKey altered by device A's rotation — want unchanged %x, got %x", peerBPub, gotB.Pub)
	}
}

func TestRoomRegistryLookupUnknownFails(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	nonce, _ := shared.RandomBytes(32)
	badProof, _ := shared.RandomBytes(32)
	if _, _, _, _, _, _, _, ok := reg.LookupSecret(nonce, badProof); ok {
		t.Fatal("LookupSecret: unexpected match on an empty registry")
	}
}

func TestRoomRegistryMultipleSecretsSameRoom(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	secretA, _ := shared.RandomBytes(32)
	secretB, _ := shared.RandomBytes(32)
	reg.AddSecret("room-1", secretA, "alice", nil, nil, nil)
	reg.AddSecret("room-1", secretB, "bob", nil, nil, nil)

	nonce, _ := shared.RandomBytes(32)

	_, roomID, label, _, _, _, _, ok := reg.LookupSecret(nonce, validProof(t, secretA, nonce))
	if !ok || roomID != "room-1" || label != "alice" {
		t.Fatalf("alice's secret: ok=%v roomID=%q label=%q", ok, roomID, label)
	}
	_, roomID, label, _, _, _, _, ok = reg.LookupSecret(nonce, validProof(t, secretB, nonce))
	if !ok || roomID != "room-1" || label != "bob" {
		t.Fatalf("bob's secret: ok=%v roomID=%q label=%q", ok, roomID, label)
	}
}

func TestRoomRegistryReplaceSecret(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	oldSecret, _ := shared.RandomBytes(32)
	newSecret, _ := shared.RandomBytes(32)
	reg.AddSecret("room-1", oldSecret, "alice", nil, nil, nil)

	reg.ReplaceSecret("room-1", oldSecret, newSecret, "alice", nil, nil, nil)

	nonce, _ := shared.RandomBytes(32)
	if _, _, _, _, _, _, _, ok := reg.LookupSecret(nonce, validProof(t, oldSecret, nonce)); ok {
		t.Fatal("ReplaceSecret: the old secret still authenticates")
	}
	_, roomID, label, _, _, _, _, ok := reg.LookupSecret(nonce, validProof(t, newSecret, nonce))
	if !ok || roomID != "room-1" || label != "alice" {
		t.Fatalf("ReplaceSecret: the new secret is invalid — ok=%v roomID=%q label=%q", ok, roomID, label)
	}
}

func TestRoomRegistryReplaceSecretNoOldSecret(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	newSecret, _ := shared.RandomBytes(32)

	// empty oldSecret: ReplaceSecret must simply add newSecret, without
	// requiring the entry to already exist.
	reg.ReplaceSecret("room-1", nil, newSecret, "carol", nil, nil, nil)

	nonce, _ := shared.RandomBytes(32)
	_, roomID, label, _, _, _, _, ok := reg.LookupSecret(nonce, validProof(t, newSecret, nonce))
	if !ok || roomID != "room-1" || label != "carol" {
		t.Fatalf("ReplaceSecret without oldSecret: ok=%v roomID=%q label=%q", ok, roomID, label)
	}
}

func TestRoomRegistryGetOrCreateRoomIdempotent(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	s1 := reg.GetOrCreateRoom("room-1")
	s2 := reg.GetOrCreateRoom("room-1")
	if s1 != s2 {
		t.Fatal("GetOrCreateRoom: repeated calls on the same roomID return different states")
	}
}

func TestRoomRegistryGetOrCreateRoomIsolation(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	s1 := reg.GetOrCreateRoom("room-1")
	s2 := reg.GetOrCreateRoom("room-2")
	if s1 == s2 {
		t.Fatal("GetOrCreateRoom: different rooms share the same state")
	}
}

func TestRoomRegistryTotalSessions(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	if reg.TotalSessions() != 0 {
		t.Fatal("TotalSessions: want 0 on an empty registry")
	}
	// GetOrCreateRoom by itself doesn't add sessions.
	reg.GetOrCreateRoom("room-1")
	if reg.TotalSessions() != 0 {
		t.Fatal("TotalSessions: want 0 without added sessions")
	}
}

// TestRoomRegistryConcurrentAccess doesn't assert application behavior: it
// exists to surface data races under `go test -race` (RoomRegistry uses a
// sync.RWMutex shared across AddSecret/GetOrCreateRoom/LookupSecret/TotalSessions).
func TestRoomRegistryConcurrentAccess(t *testing.T) {
	reg := serverhs.NewRoomRegistry()
	done := make(chan struct{})
	for i := range 20 {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			secret, _ := shared.RandomBytes(32)
			const roomID = "room-x"
			reg.AddSecret(roomID, secret, "user", nil, nil, nil)
			reg.GetOrCreateRoom(roomID)
			nonce, _ := shared.RandomBytes(32)
			roomKey, _ := shared.DeriveContactRoomKey(secret, shared.CurrentPeriod())
			proof := shared.ComputeRoomProof(roomKey, nonce)
			reg.LookupSecret(nonce, proof)
			reg.TotalSessions()
		}(i)
	}
	for range 20 {
		<-done
	}
}
