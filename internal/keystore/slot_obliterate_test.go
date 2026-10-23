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

// TestDuressLoginObliteratesRealIdentityOnDisk reproduces the exact
// sequence a real login does: create a file with a real identity (one
// saved contact) and the shared duress one, log in once with the
// duress combination (same branch unlockKeystoreSession takes), then
// confirm a second, independent load with the real combination no
// longer opens anything — on disk, not just in memory.
func TestDuressLoginObliteratesRealIdentityOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")

	real, err := New("alice")
	if err != nil {
		t.Fatalf("New(real): %v", err)
	}
	duress, err := New("alice-decoy")
	if err != nil {
		t.Fatalf("New(duress): %v", err)
	}

	session, err := CreateFile(path, "file-pw", "real-pw", "duress-pw", real, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	session.Identity.Contacts[0] = Contact{IdentityPub: []byte("a real contact's pubkey")}
	if err := session.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot: %v", err)
	}

	// Sanity check: the real combination opens and sees the contact just
	// saved, BEFORE any duress login happens.
	preSession, ok, err := LoadAndUnlock(path, "file-pw", "real-pw")
	if err != nil || !ok {
		t.Fatalf("real login before duress: ok=%v err=%v", ok, err)
	}
	if len(preSession.Identity.Contacts[0].IdentityPub) == 0 {
		t.Fatal("real contact missing before the duress login even happened")
	}

	// Same branch as unlockKeystoreSession: log in with the duress
	// combination, then obliterate every other slot immediately.
	duressSession, ok, err := LoadAndUnlock(path, "file-pw", "duress-pw")
	if err != nil || !ok {
		t.Fatalf("duress login: ok=%v err=%v", ok, err)
	}
	if !duressSession.Identity.IsDuress {
		t.Fatal("expected the duress combination to resolve to the duress identity")
	}
	if err := ObliterateOtherSlots(duressSession.Container, duressSession.Idx); err != nil {
		t.Fatalf("ObliterateOtherSlots: %v", err)
	}
	if err := WriteSlotContainer(path, duressSession.Container); err != nil {
		t.Fatalf("WriteSlotContainer: %v", err)
	}

	// The real combination must now fail completely.
	if _, ok, err := LoadAndUnlock(path, "file-pw", "real-pw"); ok || err != nil {
		t.Fatalf("real login still works after duress obliteration: ok=%v err=%v", ok, err)
	}

	// Duress itself must still log in normally afterward.
	postSession, ok, err := LoadAndUnlock(path, "file-pw", "duress-pw")
	if err != nil || !ok {
		t.Fatalf("duress login after obliteration: ok=%v err=%v", ok, err)
	}
	if !postSession.Identity.IsDuress {
		t.Fatal("duress identity lost its own IsDuress flag")
	}
}

func TestObliterateOtherSlotsDestroysEveryOtherSlot(t *testing.T) {
	c, realIdx, duressIdx, _, duressKi, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if len(c.Slots) != 3 {
		t.Fatalf("expected 3 slots at birth, got %d", len(c.Slots))
	}

	origLens := make([]int, len(c.Slots))
	for i, s := range c.Slots {
		origLens[i] = len(s.Salt) + len(s.WrapNonce) + len(s.WrappedKi) + len(s.ContentNonce) + len(s.Content)
	}

	if err := ObliterateOtherSlots(c, duressIdx); err != nil {
		t.Fatalf("ObliterateOtherSlots: %v", err)
	}

	// The real identity's password combination must no longer open
	// anything.
	if _, ok := unwrapKi(c.Slots[realIdx], "pf", "real-secret"); ok {
		t.Fatal("real slot still opens after obliteration")
	}
	// Nothing in the file should open under the real combination at
	// all — not just the index it used to live at.
	for i, s := range c.Slots {
		if i == duressIdx {
			continue
		}
		if _, ok := unwrapKi(s, "pf", "real-secret"); ok {
			t.Fatalf("slot %d unexpectedly opens under the real password after obliteration", i)
		}
	}
	// The kept (duress) slot must be completely untouched.
	gotKi, ok := unwrapKi(c.Slots[duressIdx], "pf", "duress-secret")
	if !ok || string(gotKi) != string(duressKi) {
		t.Fatal("duress slot was altered by ObliterateOtherSlots")
	}

	// Every slot's total byte size must be unchanged — no size tell.
	for i, s := range c.Slots {
		gotLen := len(s.Salt) + len(s.WrapNonce) + len(s.WrappedKi) + len(s.ContentNonce) + len(s.Content)
		if gotLen != origLens[i] {
			t.Fatalf("slot %d size changed: before=%d after=%d", i, origLens[i], gotLen)
		}
	}
}

// TestNukexObliteratesOnlyTheTriggeringRealIdentity reproduces the
// sequence runNukeOverwriteInPlace (cmd/main.go) follows after a
// /nukex-class trigger: a real identity ("alice") shares the file with
// an INDEPENDENT other real identity ("bob", never touched by alice's
// own trigger — e.g. a sibling identity in the same file) plus the
// shared duress identity. After obliterating ONLY alice's own slot, her
// combination must no longer open anything, bob's must still work
// completely unchanged, and duress must still work too.
func TestNukexObliteratesOnlyTheTriggeringRealIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")

	alice, err := New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	duress, err := New("alice-decoy")
	if err != nil {
		t.Fatalf("New(duress): %v", err)
	}

	session, err := CreateFile(path, "file-pw", "alice-pw", "duress-pw", alice, duress)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	bob, err := New("bob")
	if err != nil {
		t.Fatalf("New(bob): %v", err)
	}
	if _, _, err := session.AddRealIdentity("bob-pw", bob); err != nil {
		t.Fatalf("AddRealIdentity(bob): %v", err)
	}
	if err := session.SaveSlot(path); err != nil {
		t.Fatalf("SaveSlot after AddRealIdentity: %v", err)
	}

	// Sanity check: both real identities open before any trigger fires.
	if _, ok, err := LoadAndUnlock(path, "file-pw", "alice-pw"); err != nil || !ok {
		t.Fatalf("alice login before trigger: ok=%v err=%v", ok, err)
	}
	if _, ok, err := LoadAndUnlock(path, "file-pw", "bob-pw"); err != nil || !ok {
		t.Fatalf("bob login before trigger: ok=%v err=%v", ok, err)
	}

	// Same operation runNukeOverwriteInPlace performs: obliterate
	// ONLY alice's own slot (session.Idx), never bob's or duress's.
	if err := ObliterateSlot(session.Container, session.Idx); err != nil {
		t.Fatalf("ObliterateSlot: %v", err)
	}
	if err := WriteSlotContainer(path, session.Container); err != nil {
		t.Fatalf("WriteSlotContainer: %v", err)
	}
	// Alice's own combination must now fail completely: the triggering
	// real identity never survives.
	if _, ok, err := LoadAndUnlock(path, "file-pw", "alice-pw"); ok || err != nil {
		t.Fatalf("alice login still works after her own nukex obliteration: ok=%v err=%v", ok, err)
	}

	// bob — an unrelated real identity sharing the same file — must be
	// completely unaffected: alice's trigger must never implicate him.
	bobSession, ok, err := LoadAndUnlock(path, "file-pw", "bob-pw")
	if err != nil || !ok {
		t.Fatalf("bob login after alice's trigger: ok=%v err=%v", ok, err)
	}
	if bobSession.Identity.Username != "bob" {
		t.Fatalf("bob's identity corrupted: got username %q", bobSession.Identity.Username)
	}

	// duress must still log in normally too.
	if _, ok, err := LoadAndUnlock(path, "file-pw", "duress-pw"); err != nil || !ok {
		t.Fatalf("duress login after alice's trigger: ok=%v err=%v", ok, err)
	}
}

func TestObliterateSlotRejectsOutOfRangeIndex(t *testing.T) {
	c, _, _, _, _, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if err := ObliterateSlot(c, len(c.Slots)); err == nil {
		t.Fatal("expected an error for an out-of-range index")
	}
	if err := ObliterateSlot(c, -1); err == nil {
		t.Fatal("expected an error for a negative index")
	}
}

func TestObliterateOtherSlotsKeepsRequestedIndexByteForByte(t *testing.T) {
	c, realIdx, _, realKi, _, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	before := c.Slots[realIdx]

	if err := ObliterateOtherSlots(c, realIdx); err != nil {
		t.Fatalf("ObliterateOtherSlots: %v", err)
	}

	after := c.Slots[realIdx]
	if string(before.Salt) != string(after.Salt) ||
		string(before.WrapNonce) != string(after.WrapNonce) ||
		string(before.WrappedKi) != string(after.WrappedKi) ||
		string(before.ContentNonce) != string(after.ContentNonce) ||
		string(before.Content) != string(after.Content) {
		t.Fatal("the kept slot was mutated")
	}
	gotKi, ok := unwrapKi(c.Slots[realIdx], "pf", "real-secret")
	if !ok || string(gotKi) != string(realKi) {
		t.Fatal("kept slot no longer opens with its own password after ObliterateOtherSlots")
	}
}
