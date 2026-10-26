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

package indoor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"neutrino/internal/keystore"
)

// runBothSides runs RunSession on both ends of a net.Pipe() (an in-memory
// connection, no real network) in parallel, needed because the protocol
// is synchronous and full-duplex on the same connection.
func runBothSides(t *testing.T, identityPriv ed25519.PrivateKey, payloadA, payloadB SyncPayload) (gotByA, gotByB SyncPayload, errA, errB error) {
	t.Helper()
	connA, connB := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		gotByA, errA = RunSession(connA, 5*time.Second, identityPriv, payloadA, true, noopTombstoneRound())
	}()
	go func() {
		defer wg.Done()
		gotByB, errB = RunSession(connB, 5*time.Second, identityPriv, payloadB, false, noopTombstoneRound())
	}()
	wg.Wait()
	return
}

// noopTombstoneRound is a TombstoneRound that never has anything to
// reply or ack, used by tests that don't exercise deletion
// reconciliation.
func noopTombstoneRound() TombstoneRound {
	return TombstoneRound{
		ComputeReplies: func([]keystore.Contact) []keystore.DeletedContact { return nil },
		ApplyAndAck:    func([]keystore.DeletedContact) [][]byte { return nil },
		ConfirmAcked:   func([][]byte, []byte) {},
	}
}

func testDeviceRecord(label string) keystore.DeviceRecord {
	id := make([]byte, 16)
	rand.Read(id)
	pub := make([]byte, 32)
	rand.Read(pub)
	return keystore.DeviceRecord{DeviceID: id, DevicePub: pub, Label: label}
}

func TestRunSessionRoundtripSameIdentity(t *testing.T) {
	_, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	contactPub := make([]byte, 32)
	rand.Read(contactPub)

	payloadA := SyncPayload{
		Contacts: []keystore.Contact{{Username: "bob", IdentityPub: contactPub}},
		Device:   testDeviceRecord("laptop-A"),
	}
	payloadB := SyncPayload{
		Device: testDeviceRecord("phone-B"),
	}

	gotByA, gotByB, errA, errB := runBothSides(t, identityPriv, payloadA, payloadB)
	if errA != nil {
		t.Fatalf("initiator (A): %v", errA)
	}
	if errB != nil {
		t.Fatalf("responder (B): %v", errB)
	}

	if !bytes.Equal(gotByA.Device.DeviceID, payloadB.Device.DeviceID) {
		t.Error("A should have received the DeviceRecord sent by B")
	}
	if !bytes.Equal(gotByB.Device.DeviceID, payloadA.Device.DeviceID) {
		t.Error("B should have received the DeviceRecord sent by A")
	}
	if len(gotByB.Contacts) != 1 || gotByB.Contacts[0].Username != "bob" {
		t.Errorf("B should have received A's address book, got %+v", gotByB.Contacts)
	}
}

// TestRunSessionRejectsDifferentIdentity covers the protocol's central
// security guarantee: if the two sides do NOT have the same private key
// (different identities, not a real duplication), the challenge/response
// must fail on both sides, never a session silently established with a
// peer that doesn't prove possession of the same identity.
func TestRunSessionRejectsDifferentIdentity(t *testing.T) {
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	connA, connB := net.Pipe()
	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errA = RunSession(connA, 500*time.Millisecond, privA, SyncPayload{Device: testDeviceRecord("A")}, true, noopTombstoneRound())
	}()
	go func() {
		defer wg.Done()
		_, errB = RunSession(connB, 500*time.Millisecond, privB, SyncPayload{Device: testDeviceRecord("B")}, false, noopTombstoneRound())
	}()
	wg.Wait()

	if errA == nil {
		t.Error("the initiator with a key different from the responder's must fail, it didn't")
	}
	if errB == nil {
		t.Error("the responder with a key different from the initiator's must fail, it didn't")
	}
}

func TestIdentityHashStableAndDistinct(t *testing.T) {
	pub1 := make([]byte, 32)
	rand.Read(pub1)
	pub2 := make([]byte, 32)
	rand.Read(pub2)

	h1a := IdentityHash(pub1)
	h1b := IdentityHash(pub1)
	if !bytes.Equal(h1a, h1b) {
		t.Error("IdentityHash must be deterministic for the same pubkey")
	}
	h2 := IdentityHash(pub2)
	if bytes.Equal(h1a, h2) {
		t.Error("IdentityHash of two different pubkeys must not match (with negligible probability)")
	}
	if len(h1a) != 16 {
		t.Errorf("IdentityHash len = %d, want 16", len(h1a))
	}
}

func TestDeriveSessionKeyDeterministicBothSides(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	nonceA := make([]byte, nonceLen)
	rand.Read(nonceA)
	nonceB := make([]byte, nonceLen)
	rand.Read(nonceB)

	k1, err := DeriveSessionKey(priv, nonceA, nonceB)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveSessionKey(priv, nonceA, nonceB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveSessionKey must be deterministic for the same nonces/key, that's how both sides reach the same key without exchanging it")
	}

	otherNonceB := make([]byte, nonceLen)
	rand.Read(otherNonceB)
	k3, _ := DeriveSessionKey(priv, nonceA, otherNonceB)
	if bytes.Equal(k1, k3) {
		t.Error("different nonces must produce different session keys")
	}
}
