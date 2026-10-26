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
	"crypto/rand"
	"path/filepath"
	"testing"

	"neutrino/internal/transport"
)

func writeFreshContainer(t *testing.T, path string) (realKi, duressKi []byte, pool growthPool) {
	t.Helper()
	c, realIdx, duressIdx, realKi, duressKi, pool, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	sealIdentity(t, c, realIdx, realKi, "alice")
	sealIdentity(t, c, duressIdx, duressKi, "alice-decoy")
	if err := WriteSlotContainer(path, c); err != nil {
		t.Fatalf("WriteSlotContainer: %v", err)
	}
	return realKi, duressKi, pool
}

func TestSaveSlotOnlyTouchesOwnSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	writeFreshContainer(t, path)

	before, err := ReadSlotContainer(path)
	if err != nil {
		t.Fatalf("ReadSlotContainer (before): %v", err)
	}
	duressBefore := append([]byte{}, before.Slots[1].Content...)
	noiseBefore := append([]byte{}, before.Slots[2].Content...)

	u, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock: ok=%v err=%v", ok, err)
	}
	u.Identity.Username = "alice-renamed"
	if err := u.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	after, err := ReadSlotContainer(path)
	if err != nil {
		t.Fatalf("ReadSlotContainer (after): %v", err)
	}
	if string(after.Slots[1].Content) != string(duressBefore) {
		t.Fatal("duress slot content changed even though this session never touched it")
	}
	if string(after.Slots[2].Content) != string(noiseBefore) {
		t.Fatal("noise slot content changed even though this session never touched it")
	}

	reopened, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (reopened): ok=%v err=%v", ok, err)
	}
	if reopened.Identity.Username != "alice-renamed" {
		t.Fatalf("expected the rename to persist, got %q", reopened.Identity.Username)
	}
}

func TestSaveWithDuressUpdatesBothSlots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	_, duressKi, _ := writeFreshContainer(t, path)

	u, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock: ok=%v err=%v", ok, err)
	}
	u.Identity.Username = "alice-touched"

	duressPlain := []byte(`{"version":6,"username":"alice-decoy-touched","contacts":[]}`)
	if err := u.SaveWithDuress(path, 1, duressKi, duressPlain); err != nil {
		t.Fatalf("SaveWithDuress: %v", err)
	}

	realReopened, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (real): ok=%v err=%v", ok, err)
	}
	if realReopened.Identity.Username != "alice-touched" {
		t.Fatalf("expected real identity update to persist, got %q", realReopened.Identity.Username)
	}

	duressReopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}
	if duressReopened.Identity.Username != "alice-decoy-touched" {
		t.Fatalf("expected duress content update to persist, got %q", duressReopened.Identity.Username)
	}
}

// TestSaveSlotGeneratesRelRevocationCerts checks that SaveSlot — the
// save path cmd/main.go uses under the N-slot container format — runs
// ensureRelRevocations, which pre-computes
// DeviceRelation.RevokeIdentitySig/RevokeContentSig (consulted by
// BuildPodSnapshot/deliverPodRevokes to pick which contacts the nuke
// pod has anything to send to). Without them, every /nukex pod finds
// zero targets. TestSaveGeneratesRelRevocationCerts (keystore_test.go)
// covers Keystore.Save, and TestBuildPodSnapshot calls
// ensureRelRevocations directly as setup: this test exercises the
// production path (LoadAndUnlock → SaveSlot).
func TestSaveSlotGeneratesRelRevocationCerts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")

	// CreateFile/New, not writeFreshContainer/sealIdentity: this test
	// needs a real IdentityPrivKey (BuildPodSnapshot derives its own
	// pubkey from it) — the bare {Version,Username,Contacts} the other
	// helper seals has none, real identities created through the wizard
	// always do.
	real, err := New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	duress, err := New("alice-decoy")
	if err != nil {
		t.Fatalf("New(duress): %v", err)
	}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	contactPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (contact): %v", err)
	}
	_, relIdentityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (relIdentity): %v", err)
	}
	devicePub := "some-device-pub"
	// CreateFile already seeded Contacts[0] with an empty placeholder
	// (ContactPendingIdx bookkeeping) — append, don't assume index 0.
	u.Identity.Contacts = append(u.Identity.Contacts, Contact{
		Username:    "bob",
		IdentityPub: contactPub,
		Devices: map[string]*DeviceRelation{
			devicePub: {RelIdentityPriv: relIdentityPriv},
		},
	})

	if err := u.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	reopened, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (reopened): ok=%v err=%v", ok, err)
	}
	bob, ok := reopened.Identity.GetContactByPub(contactPub)
	if !ok {
		t.Fatal("bob contact missing after reload")
	}
	dev := bob.Devices[devicePub]
	if dev == nil || len(dev.RevokeIdentitySig) == 0 {
		t.Fatal("RevokeIdentitySig empty after SaveSlot — ensureRelRevocations never ran on the production save path")
	}

	// The actual consumer: BuildPodSnapshot must find this contact
	// as a real target, not skip it.
	addressFromPub := func(pub []byte) string { return "addr:" + string(pub) }
	snap := BuildPodSnapshot([]*Keystore{reopened.Identity}, addressFromPub, "127.0.0.1:9050", transport.KindTor)
	if len(snap.Targets) != 1 {
		t.Fatalf("BuildPodSnapshot: expected 1 target after a real SaveSlot, got %d", len(snap.Targets))
	}
}

func TestSaveSlotPersistsContainerGrowth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	_, _, pool := writeFreshContainer(t, path)

	u, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock: ok=%v err=%v", ok, err)
	}

	newIdx, newKi, _, err := u.Container.AddRealIdentity("pf", "real2", pool)
	if err != nil {
		t.Fatalf("AddRealIdentity: %v", err)
	}
	sealIdentity(t, u.Container, newIdx, newKi, "bob")

	if err := u.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	reopened, err := ReadSlotContainer(path)
	if err != nil {
		t.Fatalf("ReadSlotContainer: %v", err)
	}
	if len(reopened.Slots) != 5 {
		t.Fatalf("expected the grown container (5 slots) to persist, got %d", len(reopened.Slots))
	}

	bobUnlocked, ok, err := LoadAndUnlock(path, "pf", "real2")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (bob): ok=%v err=%v", ok, err)
	}
	if bobUnlocked.Identity.Username != "bob" {
		t.Fatalf("expected the newly added identity to persist, got %q", bobUnlocked.Identity.Username)
	}
}
