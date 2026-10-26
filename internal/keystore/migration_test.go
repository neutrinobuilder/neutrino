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
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

// TestMigrateVersion1BackfillsIdentityAndMLKEM: a version-1 identity with
// no keys must receive an Ed25519 IdentityKey, an ML-KEM-768 MLKEMKey and
// an ML-DSA-65 MLDSAKey in a single pass (fallthrough).
func TestMigrateVersion1BackfillsIdentityAndMLKEM(t *testing.T) {
	ks := &Keystore{Version: 1, Username: "alice"}
	if err := migrateVersion(ks); err != nil {
		t.Fatalf("migrateVersion: %v", err)
	}
	if ks.Version != version {
		t.Fatalf("Version = %d, want %d", ks.Version, version)
	}
	if len(ks.IdentityKey) != ed25519.PrivateKeySize {
		t.Fatalf("IdentityKey not generated: len = %d, want %d", len(ks.IdentityKey), ed25519.PrivateKeySize)
	}
	dk := ks.MLKEMDecap()
	if dk == nil {
		t.Fatal("MLKEMKey not generated: MLKEMDecap() = nil")
	}
	if len(ks.MLKEMPubBytes()) == 0 {
		t.Fatal("MLKEMPubBytes() empty after the migration")
	}
	if ks.MLDSAPrivKey() == nil {
		t.Fatal("MLDSAKey not generated: MLDSAPrivKey() = nil")
	}
	if ks.MLDSAPubKey() == nil {
		t.Fatal("MLDSAPubKey() = nil after the migration")
	}
}

// TestMigrateVersion2BackfillsMLKEMOnly: a version-2 identity already with an IdentityKey but without MLKEMKey/MLDSAKey
// must receive both, without touching the already-present Ed25519 key.
func TestMigrateVersion2BackfillsMLKEMOnly(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ks := &Keystore{Version: 2, Username: "bob", IdentityKey: []byte(priv)}
	if err := migrateVersion(ks); err != nil {
		t.Fatalf("migrateVersion: %v", err)
	}
	if ks.Version != version {
		t.Fatalf("Version = %d, want %d", ks.Version, version)
	}
	if string(ks.IdentityKey) != string(priv) {
		t.Error("pre-existing IdentityKey altered by the v2→v3 migration")
	}
	if ks.MLKEMDecap() == nil {
		t.Fatal("MLKEMKey not generated during the v2→v3 migration")
	}
	if ks.MLDSAPrivKey() == nil {
		t.Fatal("MLDSAKey not generated during the v2→v5 migration")
	}
}

// TestMigrateVersion4BackfillsMLDSAOnly: a version-4 identity (already with IdentityKey/MLKEMKey/DeviceID) but without
// MLDSAKey must receive only that one, without touching the
// already-present keys.
func TestMigrateVersion4BackfillsMLDSAOnly(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	ks := &Keystore{
		Version:     4,
		Username:    "dave",
		IdentityKey: []byte(priv),
		MLKEMKey:    mlkemDK.Bytes(),
	}
	if err := migrateVersion(ks); err != nil {
		t.Fatalf("migrateVersion: %v", err)
	}
	if ks.Version != version {
		t.Fatalf("Version = %d, want %d", ks.Version, version)
	}
	if string(ks.IdentityKey) != string(priv) {
		t.Error("pre-existing IdentityKey altered by the v4→v5 migration")
	}
	if string(ks.MLKEMKey) != string(mlkemDK.Bytes()) {
		t.Error("pre-existing MLKEMKey altered by the v4→v5 migration")
	}
	if ks.MLDSAPrivKey() == nil {
		t.Fatal("MLDSAKey not generated during the v4→v5 migration")
	}
}

// TestMigrateVersionCurrentIsNoop covers the case already at the
// current version: no key is regenerated (identical before and after).
func TestMigrateVersionCurrentIsNoop(t *testing.T) {
	ks, err := New("carol")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	origIdentity := append([]byte(nil), ks.IdentityKey...)
	origMLKEM := append([]byte(nil), ks.MLKEMKey...)
	origMLDSA := append([]byte(nil), ks.MLDSAKey...)
	if err := migrateVersion(ks); err != nil {
		t.Fatalf("migrateVersion: %v", err)
	}
	if string(ks.IdentityKey) != string(origIdentity) {
		t.Error("IdentityKey altered by a no-op migration")
	}
	if string(ks.MLKEMKey) != string(origMLKEM) {
		t.Error("MLKEMKey altered by a no-op migration")
	}
	if string(ks.MLDSAKey) != string(origMLDSA) {
		t.Error("MLDSAKey altered by a no-op migration")
	}
}

// TestMigrateVersionUnsupportedFuture covers the explicit rejection of
// an unknown future version (never silently accepted).
func TestMigrateVersionUnsupportedFuture(t *testing.T) {
	ks := &Keystore{Version: version + 1}
	if err := migrateVersion(ks); err == nil {
		t.Fatal("migrateVersion: no error for an unknown future version")
	}
}

// TestPruneOrphanPlaceholderDevicesRemovesUnconfirmedPlaceholder covers
// the real case: a contact with a device already confirmed in both
// directions PLUS a "" placeholder that never came to anything (no
// PeerRelIdentityPub/PeerRelContentPub), the placeholder must be
// removed, the real device stays intact.
func TestPruneOrphanPlaceholderDevicesRemovesUnconfirmedPlaceholder(t *testing.T) {
	ks := &Keystore{
		Contacts: []Contact{{
			Username: "bob",
			Devices: map[string]*DeviceRelation{
				"":       {RelIdentityPriv: []byte("placeholder")},
				"realdev": {RelIdentityConfirmedByPeer: true, RelContentConfirmedByPeer: true, PeerRelIdentityPub: []byte("peer-id"), PeerRelContentPub: []byte("peer-content")},
			},
		}},
	}
	if !pruneOrphanPlaceholderDevices(ks) {
		t.Fatal("pruneOrphanPlaceholderDevices: want true (one entry removed)")
	}
	devs := ks.Contacts[0].Devices
	if _, hasPh := devs[""]; hasPh {
		t.Error("the \"\" placeholder is still present")
	}
	if _, hasReal := devs["realdev"]; !hasReal {
		t.Error("the real device was removed by mistake")
	}
}

// TestPruneOrphanPlaceholderDevicesLeavesAmbiguousCaseAlone covers the
// cases where the cleanup must NOT act: a single device (nothing to
// clean up), or a placeholder that has already received the peer's keys
// (no longer a truly empty placeholder, even if not yet confirmed).
func TestPruneOrphanPlaceholderDevicesLeavesAmbiguousCaseAlone(t *testing.T) {
	ks := &Keystore{
		Contacts: []Contact{
			{
				Username: "placeholder-only",
				Devices:  map[string]*DeviceRelation{"": {RelIdentityPriv: []byte("x")}},
			},
			{
				Username: "placeholder-with-peer-pub",
				Devices: map[string]*DeviceRelation{
					"":       {PeerRelIdentityPub: []byte("something")},
					"realdev": {RelIdentityConfirmedByPeer: true, RelContentConfirmedByPeer: true},
				},
			},
		},
	}
	if pruneOrphanPlaceholderDevices(ks) {
		t.Fatal("pruneOrphanPlaceholderDevices: want false, no entry needed removing")
	}
	if _, hasPh := ks.Contacts[0].Devices[""]; !hasPh {
		t.Error("single-device contact: the placeholder shouldn't have been touched")
	}
	if _, hasPh := ks.Contacts[1].Devices[""]; !hasPh {
		t.Error("placeholder with PeerRelIdentityPub already populated: shouldn't have been removed")
	}
}
