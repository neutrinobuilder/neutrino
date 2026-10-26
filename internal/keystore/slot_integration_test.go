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
	"path/filepath"
	"testing"
)

func TestCreateFileThenLoadAndUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}

	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if len(u.Container.Slots) != 3 {
		t.Fatalf("expected 3 slots at birth, got %d", len(u.Container.Slots))
	}

	reopenedReal, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (real): ok=%v err=%v", ok, err)
	}
	if reopenedReal.Identity.Username != "alice" || reopenedReal.Identity.IsDuress {
		t.Fatalf("unexpected real identity: %+v", reopenedReal.Identity)
	}
	if len(reopenedReal.Identity.ContactPendingIdx.Pending) != 1 || len(reopenedReal.Identity.Contacts) != 1 {
		t.Fatalf("expected 1 pre-allocated empty contact, got pending=%+v contacts=%d",
			reopenedReal.Identity.ContactPendingIdx, len(reopenedReal.Identity.Contacts))
	}

	reopenedDuress, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}
	if reopenedDuress.Identity.Username != "alice-decoy" || !reopenedDuress.Identity.IsDuress {
		t.Fatalf("unexpected duress identity: %+v", reopenedDuress.Identity)
	}
}

func TestAddRealIdentityThroughUnlockedSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	bob := &Keystore{Version: version, Username: "bob", Contacts: []Contact{}}
	idx, ki, err := u.AddRealIdentity("bob-secret", bob)
	if err != nil {
		t.Fatalf("AddRealIdentity: %v", err)
	}
	if len(u.Container.Slots) != 5 {
		t.Fatalf("expected the container to grow to 5 slots, got %d", len(u.Container.Slots))
	}
	if err := u.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	bobReopened, ok, err := LoadAndUnlock(path, "pf", "bob-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (bob): ok=%v err=%v", ok, err)
	}
	if bobReopened.Identity.Username != "bob" {
		t.Fatalf("expected bob to persist, got %q", bobReopened.Identity.Username)
	}
	if got, _ := unwrapKi(u.Container.Slots[idx], "pf", "bob-secret"); string(got) != string(ki) {
		t.Fatal("bob's slot does not unwrap to the K_i returned by AddRealIdentity")
	}

	// bob must also be able to reach K_i_duress through his own
	// DuressAccess field, exactly like alice.
	bobDuressKi, err := OpenDuressAccess(bobReopened.Ki, bobReopened.Identity.DuressAccess)
	if err != nil {
		t.Fatalf("OpenDuressAccess (bob): %v", err)
	}
	aliceReopened, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (alice): ok=%v err=%v", ok, err)
	}
	aliceDuressKi, err := OpenDuressAccess(aliceReopened.Ki, aliceReopened.Identity.DuressAccess)
	if err != nil {
		t.Fatalf("OpenDuressAccess (alice): %v", err)
	}
	if string(bobDuressKi) != string(aliceDuressKi) {
		t.Fatal("bob and alice must reach the SAME shared duress K_i")
	}
}

func TestAddAndEmptyMirroredContact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	realContact := Contact{Username: "carol"}
	fakeBuilt := Contact{Username: "fake-carol"}
	_, _, _, duressIdx, duressKi, duressPlain, err := u.AddMirroredContacts([]Contact{realContact}, nil, func(map[string]bool) Contact { return fakeBuilt })
	if err != nil {
		t.Fatalf("AddMirroredContacts: %v", err)
	}
	if err := u.SaveWithDuress(path, duressIdx, duressKi, duressPlain); err != nil {
		t.Fatalf("SaveWithDuress: %v", err)
	}

	if len(u.Identity.Contacts) != 3 || u.Identity.Contacts[0].Username != "carol" {
		t.Fatalf("expected real Contacts to grow to 3 with carol at index 0, got %+v", u.Identity.Contacts)
	}

	duressReopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}
	if len(duressReopened.Identity.Contacts) != 3 || duressReopened.Identity.Contacts[0].Username != "fake-carol" {
		t.Fatalf("expected duress Contacts to mirror the fill at index 0, got %+v", duressReopened.Identity.Contacts)
	}

	realReopened, ok, err := LoadAndUnlock(path, "pf", "real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (real): ok=%v err=%v", ok, err)
	}
	dIdx, dKi, dPlain, hadMirror, err := realReopened.EmptyMirroredContact(0)
	if err != nil {
		t.Fatalf("EmptyMirroredContact: %v", err)
	}
	if !hadMirror {
		t.Fatal("expected a mirror to exist for the filled contact")
	}
	if err := realReopened.SaveWithDuress(path, dIdx, dKi, dPlain); err != nil {
		t.Fatalf("SaveWithDuress (empty): %v", err)
	}

	if realReopened.Identity.Contacts[0].Username != "" {
		t.Fatalf("expected real contact 0 emptied in place, got %+v", realReopened.Identity.Contacts[0])
	}

	duressFinal, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress final): ok=%v err=%v", ok, err)
	}
	if duressFinal.Identity.Contacts[0].Username != "" {
		t.Fatalf("expected duress contact 0 emptied in place too, got %+v", duressFinal.Identity.Contacts[0])
	}
	if len(duressFinal.Identity.Contacts) != 3 {
		t.Fatalf("emptying must never remove the slot: expected len 3, got %d", len(duressFinal.Identity.Contacts))
	}
}

// TestEmptyMirroredContactRecyclesBothSides verifies the symmetric
// recycling rule: an emptied Contact is bit-for-bit identical to a
// freshly-born one, so its index goes straight back into
// ContactPendingIdx.Pending for BOTH the real identity and duress, no
// permanent, ever-growing hole on either side, and the now-stale
// real→duress mirror mapping is dropped.
func TestEmptyMirroredContactRecyclesBothSides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	_, _, _, duressIdx, duressKi, duressPlain, err := u.AddMirroredContacts([]Contact{{Username: "carol"}}, nil, func(map[string]bool) Contact { return Contact{Username: "fake-carol"} })
	if err != nil {
		t.Fatalf("AddMirroredContacts: %v", err)
	}
	if err := u.SaveWithDuress(path, duressIdx, duressKi, duressPlain); err != nil {
		t.Fatalf("SaveWithDuress: %v", err)
	}
	realPendingBefore := len(u.Identity.ContactPendingIdx.Pending)
	mirroredDuressIdx := u.Identity.ContactMirrorDuressIdx[0]

	dIdx, dKi, dPlain, hadMirror, err := u.EmptyMirroredContact(0)
	if err != nil {
		t.Fatalf("EmptyMirroredContact: %v", err)
	}
	if !hadMirror {
		t.Fatal("expected a mirror to exist for the filled contact")
	}
	if err := u.SaveWithDuress(path, dIdx, dKi, dPlain); err != nil {
		t.Fatalf("SaveWithDuress (empty): %v", err)
	}

	if len(u.Identity.ContactPendingIdx.Pending) != realPendingBefore+1 {
		t.Fatalf("expected the emptied real index to be recycled into Pending (len %d -> %d), got %d",
			realPendingBefore, realPendingBefore+1, len(u.Identity.ContactPendingIdx.Pending))
	}
	found := false
	for _, idx := range u.Identity.ContactPendingIdx.Pending {
		if idx == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected recycled index 0 inside real Pending, got %v", u.Identity.ContactPendingIdx.Pending)
	}
	if _, stillMapped := u.Identity.ContactMirrorDuressIdx[0]; stillMapped {
		t.Fatal("expected the stale real->duress mirror mapping to be dropped after emptying")
	}

	duressReopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}
	foundDuress := false
	for _, idx := range duressReopened.Identity.ContactPendingIdx.Pending {
		if idx == mirroredDuressIdx {
			foundDuress = true
		}
	}
	if !foundDuress {
		t.Fatalf("expected the emptied duress mirror index %d to be recycled into duress's own Pending, got %v",
			mirroredDuressIdx, duressReopened.Identity.ContactPendingIdx.Pending)
	}
}

func TestEmptyMirroredContactWithoutMirrorIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{{}}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	// Index 0 here is the pre-allocated empty placeholder from CreateFile
	// never filled via AddMirroredContacts, so it has no mirror.
	_, _, _, hadMirror, err := u.EmptyMirroredContact(0)
	if err != nil {
		t.Fatalf("EmptyMirroredContact: %v", err)
	}
	if hadMirror {
		t.Fatal("expected no mirror for a contact that was never filled")
	}
}

// TestAddAndEmptyPlainContactOnDuressSession verifies that a session
// already operating as the duress identity (after PromoteDuress, or a
// direct duress login) can manage its own contacts without ever
// touching openDuressContent, there is no further duress beneath
// duress to mirror into, so AddPlainContacts/EmptyPlainContact must
// work on u.Identity alone: AddMirroredContacts/EmptyMirroredContact
// would fail there, since duress's own DuressAccess field is random
// noise (RandomDuressAccessField) that OpenDuressAccess always rejects.
func TestAddAndEmptyPlainContactOnDuressSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	if _, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	duressSession, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}

	added, updated, rejected, err := duressSession.AddPlainContacts([]Contact{{Username: "carol"}}, nil)
	if err != nil {
		t.Fatalf("AddPlainContacts: %v", err)
	}
	if added != 1 || updated != 0 || len(rejected) != 0 {
		t.Fatalf("expected added=1 updated=0 rejected=0, got added=%d updated=%d rejected=%v", added, updated, rejected)
	}
	if err := duressSession.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}
	if duressSession.Identity.Contacts[0].Username != "carol" {
		t.Fatalf("expected carol at index 0, got %+v", duressSession.Identity.Contacts[0])
	}

	reopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress reopened): ok=%v err=%v", ok, err)
	}
	if reopened.Identity.Contacts[0].Username != "carol" {
		t.Fatalf("expected carol to persist at index 0, got %+v", reopened.Identity.Contacts[0])
	}

	lenBefore := len(reopened.Identity.Contacts)
	if err := reopened.EmptyPlainContact(0); err != nil {
		t.Fatalf("EmptyPlainContact: %v", err)
	}
	if err := reopened.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot (empty): %v", err)
	}
	if reopened.Identity.Contacts[0].Username != "" {
		t.Fatalf("expected contact 0 emptied in place, got %+v", reopened.Identity.Contacts[0])
	}
	if len(reopened.Identity.Contacts) != lenBefore {
		t.Fatalf("emptying must never remove a slot: expected len %d, got %d", lenBefore, len(reopened.Identity.Contacts))
	}
}

// TestOverwriteAllContacts verifies the batch in-place overwrite
// mechanism a nuke trigger uses: every filled contact is emptied in one
// call, each mirrored duress contact is emptied identically, no Contact
// slot is ever removed on either side, and an already-empty identity is
// correctly reported as a no-op (nothing to save).
func TestOverwriteAllContacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	_, _, _, duressIdx, duressKi, duressPlain, err := u.AddMirroredContacts(
		[]Contact{{Username: "carol", IdentityPub: []byte("carol-pub-000000000000000000000")}, {Username: "dave", IdentityPub: []byte("dave-pub-0000000000000000000000")}}, nil,
		func(map[string]bool) Contact { return Contact{Username: "fake"} })
	if err != nil {
		t.Fatalf("AddMirroredContacts: %v", err)
	}
	if err := u.SaveWithDuress(path, duressIdx, duressKi, duressPlain); err != nil {
		t.Fatalf("SaveWithDuress: %v", err)
	}
	lenBefore := len(u.Identity.Contacts)

	dIdx, dKi, dPlain, emptied, err := u.OverwriteAllContacts()
	if err != nil {
		t.Fatalf("OverwriteAllContacts: %v", err)
	}
	if emptied != 2 {
		t.Fatalf("expected 2 contacts emptied, got %d", emptied)
	}
	if err := u.SaveWithDuress(path, dIdx, dKi, dPlain); err != nil {
		t.Fatalf("SaveWithDuress (overwrite): %v", err)
	}

	for i, c := range u.Identity.Contacts {
		if c.Username != "" {
			t.Fatalf("expected real contact %d emptied in place, got %+v", i, c)
		}
	}
	if len(u.Identity.ContactMirrorDuressIdx) != 0 {
		t.Fatalf("expected every real->duress mirror mapping dropped, got %+v", u.Identity.ContactMirrorDuressIdx)
	}
	if len(u.Identity.Contacts) != lenBefore {
		t.Fatalf("overwriting must never remove a slot: expected len %d, got %d", lenBefore, len(u.Identity.Contacts))
	}

	duressReopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}
	for i, c := range duressReopened.Identity.Contacts {
		if c.Username != "" {
			t.Fatalf("expected duress contact %d emptied in place too, got %+v", i, c)
		}
	}
	if len(duressReopened.Identity.Contacts) != lenBefore {
		t.Fatalf("overwriting must never remove a slot on duress either: expected len %d, got %d", lenBefore, len(duressReopened.Identity.Contacts))
	}

	// A second call on an already-empty identity is a correctly-reported no-op.
	_, _, _, emptiedAgain, err := u.OverwriteAllContacts()
	if err != nil {
		t.Fatalf("OverwriteAllContacts (already empty): %v", err)
	}
	if emptiedAgain != 0 {
		t.Fatalf("expected no-op on an already-empty identity, got emptied=%d", emptiedAgain)
	}
}

// TestPromoteDuress verifies that promoting duress from a real
// identity's session returns an UnlockedSlot that resolves to the same
// slot/content a direct duress login would, and that it's independently
// usable afterward (e.g. AddMirroredContacts on the promoted session).
func TestPromoteDuress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	directDuress, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress): ok=%v err=%v", ok, err)
	}

	promoted, err := u.PromoteDuress()
	if err != nil {
		t.Fatalf("PromoteDuress: %v", err)
	}
	if promoted.Idx != directDuress.Idx {
		t.Fatalf("expected the same slot index as a direct duress login, got %d vs %d", promoted.Idx, directDuress.Idx)
	}
	if string(promoted.Ki) != string(directDuress.Ki) {
		t.Fatal("expected the same K_i as a direct duress login")
	}
	if promoted.Identity.Username != "alice-decoy" || !promoted.Identity.IsDuress {
		t.Fatalf("unexpected promoted identity: %+v", promoted.Identity)
	}

	// A plain mutation (never through AddMirroredContacts/
	// EmptyMirroredContact, those assume u.Identity.DuressAccess opens
	// a REAL "duress beneath it", which duress's own is deliberately
	// random noise, not usable this way) persists
	// correctly via the promoted session's own SaveSlot.
	promoted.Identity.DeviceLabel = "promoted-session"
	if err := promoted.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot (promoted): %v", err)
	}

	reopened, ok, err := LoadAndUnlock(path, "pf", "duress-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (duress, after promoted save): ok=%v err=%v", ok, err)
	}
	if reopened.Identity.DeviceLabel != "promoted-session" {
		t.Fatalf("expected the promoted session's write to persist, got %+v", reopened.Identity.DeviceLabel)
	}
}

func TestRewrapOwnSlotChangesPasswordNotContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	real := &Keystore{Version: version, Username: "alice", Contacts: []Contact{}}
	duress := &Keystore{Version: version, Username: "alice-decoy", Contacts: []Contact{}}
	u, err := CreateFile(path, "pf", "real-secret", "duress-secret", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	if err := u.RewrapOwnSlot("pf", "new-real-secret"); err != nil {
		t.Fatalf("RewrapOwnSlot: %v", err)
	}
	if err := u.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	if _, ok, _ := LoadAndUnlock(path, "pf", "real-secret"); ok {
		t.Fatal("expected the OLD password to no longer open the slot")
	}
	reopened, ok, err := LoadAndUnlock(path, "pf", "new-real-secret")
	if err != nil || !ok {
		t.Fatalf("LoadAndUnlock (new password): ok=%v err=%v", ok, err)
	}
	if reopened.Identity.Username != "alice" {
		t.Fatalf("expected content unchanged after rewrap, got username %q", reopened.Identity.Username)
	}
}
