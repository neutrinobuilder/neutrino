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

package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"neutrino/internal/keystore"
)

// TestRelKeysForDeviceRejectsRevokedIdentity verifies that a device with
// RevokedIdentity=true (a verified "rel_revoke" knock) must no longer
// authenticate a handshake — treated as if the device didn't exist at
// all (ok=false), the same outcome as a contact/device not found or
// incomplete keys.
func TestRelKeysForDeviceRejectsRevokedIdentity(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devPub := []byte("devpub")
	peerRelIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	myPriv := make([]byte, ed25519.PrivateKeySize)
	rand.Read(myPriv)

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(keystore.Contact{
		Username:    "bob",
		IdentityPub: bobPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(devPub): {
				RelIdentityPriv:    myPriv,
				PeerRelIdentityPub: peerRelIdentPub,
			},
		},
	})

	// Before revocation: resolves normally.
	if _, _, ok := ks.RelKeysForDevice(bobPub, devPub); !ok {
		t.Fatal("want ok=true before any revocation")
	}

	if !ks.MarkDeviceRevoked(bobPub, devPub, true, false) {
		t.Fatal("MarkDeviceRevoked must find the device")
	}

	if _, _, ok := ks.RelKeysForDevice(bobPub, devPub); ok {
		t.Error("RelKeysForDevice must refuse a device with RevokedIdentity=true")
	}
}

// TestRelKeysForDeviceIgnoresRevokedContent verifies that
// RevokedContent (without RevokedIdentity) doesn't prevent the
// handshake from authenticating — the two revocations are independent,
// the same principle already established for
// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer.
func TestRelKeysForDeviceIgnoresRevokedContent(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devPub := []byte("devpub")
	peerRelIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	myPriv := make([]byte, ed25519.PrivateKeySize)
	rand.Read(myPriv)

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(keystore.Contact{
		Username:    "bob",
		IdentityPub: bobPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(devPub): {
				RelIdentityPriv:    myPriv,
				PeerRelIdentityPub: peerRelIdentPub,
			},
		},
	})

	if !ks.MarkDeviceRevoked(bobPub, devPub, false, true) {
		t.Fatal("MarkDeviceRevoked must find the device")
	}

	if _, _, ok := ks.RelKeysForDevice(bobPub, devPub); !ok {
		t.Error("an isolated RevokedContent must not block the handshake (only Identity counts here)")
	}
}

// TestRelEstablishedDeviceAndRelRevoked covers how a revocation shows in
// the contact list: a revoked device never counts as established, and
// the contact is "revoked" only if no other device still has a valid
// relationship.
func TestRelEstablishedDeviceAndRelRevoked(t *testing.T) {
	established := func(revokedIdentity, revokedContent bool) *keystore.DeviceRelation {
		peerContentPub, _, _ := ed25519.GenerateKey(rand.Reader)
		myContentPriv := make([]byte, ed25519.PrivateKeySize)
		rand.Read(myContentPriv)
		return &keystore.DeviceRelation{
			RelContentPriv:    myContentPriv,
			PeerRelContentPub: peerContentPub,
			RevokedIdentity:   revokedIdentity,
			RevokedContent:    revokedContent,
		}
	}
	cases := []struct {
		name        string
		devices     map[string]*keystore.DeviceRelation
		wantEstab   bool
		wantRevoked bool
	}{
		{"valid", map[string]*keystore.DeviceRelation{"a": established(false, false)}, true, false},
		{"identity revoked", map[string]*keystore.DeviceRelation{"a": established(true, false)}, false, true},
		{"content revoked", map[string]*keystore.DeviceRelation{"a": established(false, true)}, false, true},
		{"one revoked, one valid", map[string]*keystore.DeviceRelation{"a": established(false, true), "b": established(false, false)}, true, false},
		{"no device", nil, false, false},
	}
	for _, tc := range cases {
		c := keystore.Contact{Username: "bob", Devices: tc.devices}
		dev, ok := c.RelEstablishedDevice()
		if ok != tc.wantEstab {
			t.Errorf("%s: RelEstablishedDevice ok=%v, want %v", tc.name, ok, tc.wantEstab)
		}
		if ok && (dev.RevokedIdentity || dev.RevokedContent) {
			t.Errorf("%s: RelEstablishedDevice returned a revoked device", tc.name)
		}
		if got := c.RelRevoked(); got != tc.wantRevoked {
			t.Errorf("%s: RelRevoked=%v, want %v", tc.name, got, tc.wantRevoked)
		}
	}
}
