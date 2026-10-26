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
	"testing"

	"neutrino/internal/client"
	"neutrino/internal/keystore"
)

// TestContentPeerPubCandidatesForExcludesRevoked verifies that a device
// with RevokedContent=true must never appear among the candidates for
// verifying a message signature, neither as an exact DevicePub match,
// nor in the fallback over all known devices.
func TestContentPeerPubCandidatesForExcludesRevoked(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	revokedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	livePeerContentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	revokedDevicePub := []byte("revoked-device")
	liveDevicePub := []byte("live-device")

	tab := &roomTab{}
	m := &model{
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				string(revokedDevicePub): {PeerRelContentPub: revokedPub, RevokedContent: true},
				string(liveDevicePub):    {PeerRelContentPub: livePeerContentPub},
			},
		}},
	}

	// Exact DevicePub match on a revoked device: no candidates.
	cands := m.contentPeerPubCandidatesFor(tab, client.MemberKeyOf(bobPub), revokedDevicePub)
	if len(cands) != 0 {
		t.Errorf("want 0 candidates for a device revoked by exact DevicePub, got %d", len(cands))
	}

	// Fallback over all known devices: the revoked one must never appear,
	// only the live one.
	cands = m.contentPeerPubCandidatesFor(tab, client.MemberKeyOf(bobPub), nil)
	if len(cands) != 1 {
		t.Fatalf("want exactly 1 candidate (only the live device), got %d", len(cands))
	}
	if string(cands[0].pub) != string(livePeerContentPub) {
		t.Error("the returned candidate is not the live device's")
	}
}

// TestContentPeerKeysForExcludesRevoked verifies the same principle for
// contentPeerKeysFor (used to encrypt files/contact cards toward the peer
// AND to verify an incoming file_announce), a revoked device must never
// be chosen.
func TestContentPeerKeysForExcludesRevoked(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	revokedPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tab := &roomTab{}
	m := &model{
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"onlyDevice": {PeerRelContentPub: revokedPub, RevokedContent: true},
			},
		}},
	}

	if _, _, _, _, known := m.contentPeerKeysFor(tab, client.MemberKeyOf(bobPub)); known {
		t.Error("contentPeerKeysFor must not return a device with RevokedContent=true")
	}
}
