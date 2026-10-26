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

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"neutrino/internal/shared"
	"neutrino/internal/transport"
)

func TestBuildPodSnapshot(t *testing.T) {
	ks, err := New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	contactIdentityPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, relIdentityPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	devicePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ks.Contacts = append(ks.Contacts, Contact{
		Username:    "bob",
		IdentityPub: contactIdentityPub,
		Devices: map[string]*DeviceRelation{
			string(devicePub): {
				RelIdentityPriv: relIdentityPriv,
			},
		},
	})
	ks.ensureRelRevocations()

	addressFromPub := func(pub []byte) string { return "addr:" + string(pub) }

	snap := BuildPodSnapshot([]*Keystore{ks}, addressFromPub, "127.0.0.1:9050", transport.KindTor)

	if len(snap.Targets) != 1 {
		t.Fatalf("Targets = %d, want 1", len(snap.Targets))
	}
	target := snap.Targets[0]
	if !bytes.Equal(target.ContactIdentityPub, contactIdentityPub) {
		t.Errorf("ContactIdentityPub = %x, want %x", target.ContactIdentityPub, contactIdentityPub)
	}
	if !bytes.Equal(target.DevicePub, devicePub) {
		t.Errorf("DevicePub = %x, want %x", target.DevicePub, devicePub)
	}
	wantSig := ks.Contacts[0].Devices[string(devicePub)].RevokeIdentitySig
	if !bytes.Equal(target.IdentitySig, wantSig) {
		t.Errorf("IdentitySig mismatch")
	}
	if len(target.IdentitySig) == 0 {
		t.Fatal("IdentitySig empty, ensureRelRevocations should have populated it")
	}
	if len(target.DHTag) == 0 {
		t.Fatal("DHTag empty, the recipient's server would silently ignore this knock")
	}
	wantTag, err := shared.KnockDHTag(ks.IdentityPrivKey(), ed25519.PublicKey(contactIdentityPub))
	if err != nil {
		t.Fatalf("KnockDHTag: %v", err)
	}
	if !bytes.Equal(target.DHTag, wantTag) {
		t.Errorf("DHTag mismatch")
	}
	if target.FromUsername != "alice" {
		t.Errorf("FromUsername = %q, want %q", target.FromUsername, "alice")
	}
	if !bytes.Equal(target.FromIdentityPub, ks.IdentityPrivKey().Public().(ed25519.PublicKey)) {
		t.Errorf("FromIdentityPub mismatch")
	}

	if snap.ProxyAddr != "127.0.0.1:9050" || snap.NetKind != transport.KindTor {
		t.Errorf("snapshot header mismatch: %+v", snap)
	}

	// The whole point of the snapshot is to carry nothing an attacker
	// could use to decrypt/impersonate, verify no private key material
	// (RelIdentityPriv, the root IdentityKey, etc.) ever reaches the
	// marshaled form. DHTag is deliberately NOT covered by this check:
	// it's a derived, non-reversible artifact (can't recover the private
	// key from it), not the key itself.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(raw, relIdentityPriv) {
		t.Fatal("snapshot JSON leaks RelIdentityPriv")
	}
	if bytes.Contains(raw, ks.IdentityPrivKey()) {
		t.Fatal("snapshot JSON leaks root IdentityPrivKey")
	}
}

func TestBuildPodSnapshotSkipsContactsWithNoRevocation(t *testing.T) {
	ks, err := New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	contactIdentityPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	devicePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ks.Contacts = append(ks.Contacts, Contact{
		Username:    "bob",
		IdentityPub: contactIdentityPub,
		Devices: map[string]*DeviceRelation{
			string(devicePub): {}, // no RelIdentityPriv/RelContentPriv ever set, nothing to revoke
		},
	})

	snap := BuildPodSnapshot([]*Keystore{ks}, func(pub []byte) string { return "addr:" + string(pub) }, "", transport.KindTor)
	if len(snap.Targets) != 0 {
		t.Fatalf("Targets = %d, want 0 (no revocation certs available)", len(snap.Targets))
	}
}
