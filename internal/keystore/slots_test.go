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
	"encoding/json"
	"testing"
)

func TestSlotRoundTrip(t *testing.T) {
	ki, err := newSlotKi()
	if err != nil {
		t.Fatalf("newSlotKi: %v", err)
	}
	s, err := newSlot(ki, "password_file", "password_identity")
	if err != nil {
		t.Fatalf("newSlot: %v", err)
	}
	if err := sealSlotContent(&s, ki, []byte(`{"hello":"world"}`)); err != nil {
		t.Fatalf("sealSlotContent: %v", err)
	}

	gotKi, ok := unwrapKi(s, "password_file", "password_identity")
	if !ok {
		t.Fatal("unwrapKi: expected ok with correct password combination")
	}
	plain, err := openSlotContent(s, gotKi)
	if err != nil {
		t.Fatalf("openSlotContent: %v", err)
	}
	if string(plain) != `{"hello":"world"}` {
		t.Fatalf("content mismatch: got %q", plain)
	}
}

func TestSlotWrongPassword(t *testing.T) {
	ki, _ := newSlotKi()
	s, err := newSlot(ki, "password_file", "password_identity")
	if err != nil {
		t.Fatalf("newSlot: %v", err)
	}
	if _, ok := unwrapKi(s, "password_file", "wrong"); ok {
		t.Fatal("unwrapKi: expected failure with wrong password_identity")
	}
	if _, ok := unwrapKi(s, "wrong", "password_identity"); ok {
		t.Fatal("unwrapKi: expected failure with wrong password_file")
	}
}

func TestSlotContentOnlyGrows(t *testing.T) {
	ki, _ := newSlotKi()
	s, _ := newSlot(ki, "pf", "pi")
	if err := sealSlotContent(&s, ki, []byte("short")); err != nil {
		t.Fatalf("sealSlotContent (short): %v", err)
	}
	if err := sealSlotContent(&s, ki, []byte("a much longer payload than before")); err != nil {
		t.Fatalf("sealSlotContent (long): %v", err)
	}
	plain, err := openSlotContent(s, ki)
	if err != nil {
		t.Fatalf("openSlotContent: %v", err)
	}
	if string(plain) != "a much longer payload than before" {
		t.Fatalf("content mismatch: got %q", plain)
	}
}

func TestNoiseSlotHasNonTrivialContent(t *testing.T) {
	// An empty Content/ContentNonce would be a size tell visible to
	// anyone with the raw file, no password needed (AES-GCM ciphertext
	// length reveals plaintext length) — a noise slot's content must be
	// roughly the same size
	// as a freshly-created real identity's own bare content, not empty.
	noise, err := newNoiseSlot()
	if err != nil {
		t.Fatalf("newNoiseSlot: %v", err)
	}
	if len(noise.Content) == 0 {
		t.Fatal("noise slot has empty content — distinguishable from a real/duress slot with zero knowledge of any password")
	}

	real, err := newSlotKi()
	if err != nil {
		t.Fatalf("newSlotKi: %v", err)
	}
	realSlot, err := newSlot(real, "pf", "pi")
	if err != nil {
		t.Fatalf("newSlot: %v", err)
	}
	// Same bare baseline newNoiseSlot itself uses (New("")) — the noise
	// slot is not trying to look like a full CreateFile identity
	// (Contacts/ContactPendingIdx/DuressAccess are the additional
	// "believable decoy" layer that only duress needs).
	filler, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plain, err := json.Marshal(filler)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := sealSlotContent(&realSlot, real, plain); err != nil {
		t.Fatalf("sealSlotContent: %v", err)
	}

	diff := len(noise.Content) - len(realSlot.Content)
	if diff < -32 || diff > 32 {
		t.Fatalf("noise slot content size (%d) differs too much from a bare identity's (%d) — a potential size tell", len(noise.Content), len(realSlot.Content))
	}
}

func TestNoiseSlotIndistinguishableShape(t *testing.T) {
	real, err := newSlot(mustKi(t), "pf", "pi")
	if err != nil {
		t.Fatalf("newSlot: %v", err)
	}
	noise, err := newNoiseSlot()
	if err != nil {
		t.Fatalf("newNoiseSlot: %v", err)
	}
	if len(real.Salt) != len(noise.Salt) || len(real.WrapNonce) != len(noise.WrapNonce) || len(real.WrappedKi) != len(noise.WrappedKi) {
		t.Fatalf("noise slot shape differs from a real slot: real=%+v noise=%+v",
			struct{ Salt, WrapNonce, WrappedKi int }{len(real.Salt), len(real.WrapNonce), len(real.WrappedKi)},
			struct{ Salt, WrapNonce, WrappedKi int }{len(noise.Salt), len(noise.WrapNonce), len(noise.WrappedKi)})
	}
	// Nobody has the random password used internally, so no caller-known
	// combination should ever open a noise slot.
	if _, ok := unwrapKi(noise, "pf", "pi"); ok {
		t.Fatal("noise slot unexpectedly opened by an unrelated password combination")
	}
}

func TestPasswordIdentityCollides(t *testing.T) {
	ki1, _ := newSlotKi()
	s1, err := newSlot(ki1, "pf", "alice-secret")
	if err != nil {
		t.Fatalf("newSlot: %v", err)
	}
	slots := []slotEntry{s1}

	if !passwordIdentityCollides(slots, "pf", "alice-secret") {
		t.Fatal("expected collision: same password_file+password_identity as an existing slot")
	}
	if passwordIdentityCollides(slots, "pf", "bob-secret") {
		t.Fatal("unexpected collision: different password_identity")
	}
	if passwordIdentityCollides(slots, "other-file-pw", "alice-secret") {
		t.Fatal("unexpected collision: different password_file")
	}
}

func mustKi(t *testing.T) []byte {
	t.Helper()
	ki, err := newSlotKi()
	if err != nil {
		t.Fatalf("newSlotKi: %v", err)
	}
	return ki
}
