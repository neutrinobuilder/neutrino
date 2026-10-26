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
	"crypto/rand"
	"strings"
	"testing"

	"neutrino/internal/keystore"
	"neutrino/internal/shared"
)

// TestApplyRelRevokeValidMarksDeviceRevoked verifies that a valid
// rel_revoke announcement (certified by the already-known per-contact
// RelIdentityKey, the self-signed revocation certificate, see
// shared.SignRelRevoke) applies the revocation on the correct device and
// sends an ack.
func TestApplyRelRevokeValidMarksDeviceRevoked(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerRelIdentPub, peerRelIdentPriv, _ := ed25519.GenerateKey(rand.Reader)
	myPub, _, _ := ed25519.GenerateKey(rand.Reader)

	var markedPub, markedDevicePub []byte
	var markedIdentity, markedContent bool
	m := &model{
		myUsername:    "alice",
		myIdentityPub: myPub,
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {PeerRelIdentityPub: peerRelIdentPub},
			},
		}},
		markDeviceRevoked: func(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool {
			markedPub = pub
			markedDevicePub = devicePub
			markedIdentity = revokeIdentity
			markedContent = revokeContent
			return true
		},
	}

	sig := shared.SignRelRevoke(peerRelIdentPriv, "bob")
	cmd := m.applyRelRevoke(shared.KnockPayload{
		Type: "rel_revoke", FromUsername: "bob", FromIdentityPub: bobPub,
		RelRevoke: &shared.RelRevokePayload{DevicePub: []byte("dp"), IdentitySig: sig},
	})
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd for a valid announcement")
	}
	if _, ok := cmd().(localDisplayMsg); !ok {
		t.Fatalf("want localDisplayMsg from the resulting tea.Cmd")
	}
	if string(markedPub) != string(bobPub) {
		t.Errorf("markDeviceRevoked called with pub = %x, want %x", markedPub, bobPub)
	}
	if string(markedDevicePub) != "dp" {
		t.Errorf("markDeviceRevoked called with devicePub = %q, want \"dp\"", markedDevicePub)
	}
	if !markedIdentity {
		t.Error("revokeIdentity: want true for a valid IdentitySig")
	}
	if markedContent {
		t.Error("revokeContent must not be true: no ContentSig in the payload")
	}
	// The in-memory device follows at once.
	if dev := m.contacts[0].Devices["d"]; !dev.RevokedIdentity || dev.RevokedContent {
		t.Errorf("in-memory device: RevokedIdentity=%v RevokedContent=%v, want true/false", dev.RevokedIdentity, dev.RevokedContent)
	}
	if !m.contacts[0].RelRevoked() {
		t.Error("in-memory contact not reported as revoked")
	}
}

// TestApplyRelRevokeForgedSigIsIgnored covers the symmetric case: a
// signature not certified by the known per-relationship RelIdentityKey
// must not apply anything.
func TestApplyRelRevokeForgedSigIsIgnored(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerRelIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	var markCalled bool
	m := &model{
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {PeerRelIdentityPub: peerRelIdentPub},
			},
		}},
		markDeviceRevoked: func(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool {
			markCalled = true
			return true
		},
	}

	sig := shared.SignRelRevoke(wrongPriv, "bob")
	cmd := m.applyRelRevoke(shared.KnockPayload{
		Type: "rel_revoke", FromUsername: "bob", FromIdentityPub: bobPub,
		RelRevoke: &shared.RelRevokePayload{DevicePub: []byte("dp"), IdentitySig: sig},
	})
	if cmd != nil {
		t.Fatal("want a nil tea.Cmd: a non-genuine signature must apply nothing")
	}
	if markCalled {
		t.Error("markDeviceRevoked must never be called for a non-genuine signature")
	}
	if dev := m.contacts[0].Devices["d"]; dev.RevokedIdentity || dev.RevokedContent {
		t.Error("a forged revocation changed the in-memory device")
	}
}

// TestApplyRelRevokeAckMarksSiblingRevocationAcked verifies that an
// incoming rel_revoke_ack updates the pool through AckSiblingRevocation
// (best-effort, no signature to verify, fire-and-forget).
func TestApplyRelRevokeAckMarksSiblingRevocationAcked(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)

	var ackedPub, ackedDevicePub []byte
	m := &model{
		contacts: []ContactInfo{{Username: "bob", IdentityPub: bobPub}},
		ackSiblingRevocation: func(pub, peerDevicePub []byte) bool {
			ackedPub = pub
			ackedDevicePub = peerDevicePub
			return true
		},
	}
	cmd := m.applyRelRevokeAck(shared.KnockPayload{
		Type: "rel_revoke_ack", FromUsername: "bob", FromIdentityPub: bobPub,
		RelRevoke: &shared.RelRevokePayload{DevicePub: []byte("dp")},
	})
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd")
	}
	cmd()
	if string(ackedPub) != string(bobPub) {
		t.Errorf("ackSiblingRevocation called with pub = %x, want %x", ackedPub, bobPub)
	}
	if string(ackedDevicePub) != "dp" {
		t.Errorf("ackSiblingRevocation called with peerDevicePub = %q, want \"dp\"", ackedDevicePub)
	}
}

// TestRenderContactLineRevoked verifies that a contact whose only
// relationship has been revoked shows [REVOKED] instead of a [REL:...]
// fingerprint, and that the ContactInfo helpers agree with the keystore
// ones.
func TestRenderContactLineRevoked(t *testing.T) {
	peerContentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	myContentPriv := make([]byte, ed25519.PrivateKeySize)
	rand.Read(myContentPriv)
	dev := &keystore.DeviceRelation{RelContentPriv: myContentPriv, PeerRelContentPub: peerContentPub}
	c := ContactInfo{Username: "bob", Devices: map[string]*keystore.DeviceRelation{"a": dev}}
	m := &model{contacts: []ContactInfo{c}}

	line := m.renderContactLine(c)
	if !strings.Contains(line, "[REL:") || strings.Contains(line, "[REVOKED]") {
		t.Fatalf("valid relationship: want [REL:...], got %q", line)
	}

	dev.RevokedContent = true
	if _, ok := c.RelEstablishedDevice(); ok {
		t.Fatal("a revoked device must not count as established")
	}
	if !c.RelRevoked() {
		t.Fatal("want RelRevoked=true with the only device revoked")
	}
	line = m.renderContactLine(c)
	if !strings.Contains(line, "[REVOKED]") || strings.Contains(line, "[REL:") {
		t.Fatalf("revoked relationship: want [REVOKED], got %q", line)
	}
}
