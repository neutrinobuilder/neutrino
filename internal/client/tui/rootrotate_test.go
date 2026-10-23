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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"neutrino/internal/keystore"
	"neutrino/internal/shared"
)

// TestApplyRootRotateValidUpdatesContactIdentity verifies that a valid
// root_rotate announcement (certified by the sender's per-contact
// RelIdentityKey, never by its old root) applies the contact's new
// IdentityPub right away.
func TestApplyRootRotateValidUpdatesContactIdentity(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerRelIdentPub, peerRelIdentPriv, _ := ed25519.GenerateKey(rand.Reader)
	myPub, _, _ := ed25519.GenerateKey(rand.Reader)

	var updatedPub []byte
	var updatedNewIdentityPub ed25519.PublicKey
	m := &model{
		myUsername:    "alice",
		myIdentityPub: myPub,
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			NetAddr:     shared.OnionAddressFromPub(bobPub),
			Verified:    true,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {PeerRelIdentityPub: peerRelIdentPub, Address: shared.OnionAddressFromPub(bobPub)},
			},
		}},
		updateContactRootIdentity: func(pub []byte, newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte) error {
			updatedPub = pub
			updatedNewIdentityPub = newIdentityPub
			return nil
		},
	}

	newIdentityPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := shared.NowTS()
	sig := shared.SignRootRotation(peerRelIdentPriv, newIdentityPub, "bob", ts)

	cmd := m.applyRootRotate(shared.KnockPayload{
		Type: "root_rotate", FromUsername: "bob", FromIdentityPub: bobPub,
		RootRotate: &shared.RootRotatePayload{NewIdentityPub: newIdentityPub, Sig: sig, Ts: ts},
	})
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd for a valid announcement")
	}
	if _, ok := cmd().(localDisplayMsg); !ok {
		t.Fatalf("want localDisplayMsg from the resulting tea.Cmd")
	}
	if string(updatedPub) != string(bobPub) {
		t.Errorf("updateContactRootIdentity called with pub = %x, want %x", updatedPub, bobPub)
	}
	if string(updatedNewIdentityPub) != string(newIdentityPub) {
		t.Error("updateContactRootIdentity didn't receive the announced new IdentityPub")
	}
	// The in-memory contact follows at once: later knocks and invites go
	// to the new root and to the new root-derived address.
	c := m.contacts[0]
	newAddr := shared.OnionAddressFromPub(newIdentityPub)
	if !ed25519.PublicKey(c.IdentityPub).Equal(newIdentityPub) || c.NetAddr != newAddr || c.Verified {
		t.Errorf("in-memory contact not updated: pub=%x addr=%s verified=%v", c.IdentityPub, c.NetAddr, c.Verified)
	}
	if got := c.Devices["d"].Address; got != newAddr {
		t.Errorf("device address = %s, want %s", got, newAddr)
	}
}

// TestApplyRootRotateForgedSigIsIgnored covers the symmetric case: a
// signature not certified by the known per-contact RelIdentityKey must not
// apply anything.
func TestApplyRootRotateForgedSigIsIgnored(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerRelIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)

	var updateCalled bool
	m := &model{
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {PeerRelIdentityPub: peerRelIdentPub},
			},
		}},
		updateContactRootIdentity: func(pub []byte, newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte) error {
			updateCalled = true
			return nil
		},
	}

	newIdentityPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	ts := shared.NowTS()
	sig := shared.SignRootRotation(wrongPriv, newIdentityPub, "bob", ts)

	cmd := m.applyRootRotate(shared.KnockPayload{
		Type: "root_rotate", FromUsername: "bob", FromIdentityPub: bobPub,
		RootRotate: &shared.RootRotatePayload{NewIdentityPub: newIdentityPub, Sig: sig, Ts: ts},
	})
	if cmd != nil {
		t.Fatal("want a nil tea.Cmd: a non-genuine signature must apply nothing")
	}
	if updateCalled {
		t.Error("updateContactRootIdentity must never be called for a non-genuine signature")
	}
}

// TestApplyRootRotateAckUpdatesPending verifies that an incoming
// root_rotate_ack removes the sender from the pending lists and attempts
// finalization (no time-based expiry).
func TestApplyRootRotateAckUpdatesPending(t *testing.T) {
	var ackedPub []byte
	var finalizeCalled bool
	m := &model{
		ackRootRotationContact: func(pub []byte) bool {
			ackedPub = pub
			return true
		},
		maybeFinalizeRootRotation: func() {
			finalizeCalled = true
		},
	}
	cmd := m.applyRootRotateAck(shared.KnockPayload{Type: "root_rotate_ack", FromUsername: "bob", FromIdentityPub: testPub("bob")})
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd")
	}
	cmd()
	if !bytes.Equal(ackedPub, testPub("bob")) {
		t.Errorf("ackRootRotationContact called with %x, want bob's key", ackedPub)
	}
	if !finalizeCalled {
		t.Error("maybeFinalizeRootRotation must be called after every ack")
	}
}

// TestCmdStartRelRotationRejectsWhileRootRotationPending covers the inverse
// guard: starting a Rel rotation while a root rotation is still pending
// toward the same contact must be rejected — never two concurrent
// transitions on the same relationship.
func TestCmdStartRelRotationRejectsWhileRootRotationPending(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var startCalled bool
	m := &model{
		contacts:            []ContactInfo{{Username: "bob", IdentityPub: bobPub}},
		rootRotationPending: func() ([][]byte, [][]byte) { return [][]byte{bobPub}, nil },
		startRelIdentityRotationByPub: func(pub []byte) (map[string]shared.RelSigningKey, error) {
			startCalled = true
			return nil, nil
		},
	}
	cmd := m.cmdStartRelRotation("bob", "identity")
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd")
	}
	msg := cmd()
	ld, ok := msg.(localDisplayMsg)
	if !ok {
		t.Fatalf("want localDisplayMsg, got %T", msg)
	}
	if !ld.isError {
		t.Error("want an error message")
	}
	if startCalled {
		t.Error("startRelIdentityRotationByPub must never be called while a root rotation is pending toward this contact")
	}
}

// TestCmdStartRelRotationProceedsWithoutRootRotationPending covers the
// symmetric case: no root rotation pending toward the contact, the Rel
// rotation proceeds normally.
func TestCmdStartRelRotationProceedsWithoutRootRotationPending(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var startCalled bool
	m := &model{
		contacts: []ContactInfo{{Username: "bob", IdentityPub: bobPub}},
		startRelIdentityRotationByPub: func(pub []byte) (map[string]shared.RelSigningKey, error) {
			startCalled = true
			return map[string]shared.RelSigningKey{}, nil
		},
	}
	cmd := m.cmdStartRelRotation("bob", "identity")
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd")
	}
	cmd()
	if !startCalled {
		t.Error("startRelIdentityRotationByPub must be called when no root rotation is pending")
	}
}
