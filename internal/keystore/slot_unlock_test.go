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

// sealIdentity marshals a minimal Keystore and seals it into slot idx
// under ki — a test helper for a slot holding a bare identity.
func sealIdentity(t *testing.T, c *slotContainer, idx int, ki []byte, username string) {
	t.Helper()
	ks := &Keystore{Version: version, Username: username, Contacts: []Contact{}}
	plain, err := json.Marshal(ks)
	if err != nil {
		t.Fatalf("marshal keystore: %v", err)
	}
	if err := sealSlotContent(&c.Slots[idx], ki, plain); err != nil {
		t.Fatalf("sealSlotContent: %v", err)
	}
}

func TestUnlockSlotFindsRealAndDuress(t *testing.T) {
	c, realIdx, duressIdx, realKi, duressKi, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	sealIdentity(t, c, realIdx, realKi, "alice")
	sealIdentity(t, c, duressIdx, duressKi, "alice-decoy")

	idx, ki, ks, ok, err := UnlockSlot(c, "pf", "real-secret")
	if err != nil {
		t.Fatalf("UnlockSlot (real): %v", err)
	}
	if !ok || idx != realIdx || ks.Username != "alice" || string(ki) != string(realKi) {
		t.Fatalf("expected real identity 'alice' at idx %d, got ok=%v idx=%d username=%q", realIdx, ok, idx, ks.Username)
	}

	idx, ki, ks, ok, err = UnlockSlot(c, "pf", "duress-secret")
	if err != nil {
		t.Fatalf("UnlockSlot (duress): %v", err)
	}
	if !ok || idx != duressIdx || ks.Username != "alice-decoy" || string(ki) != string(duressKi) {
		t.Fatalf("expected duress identity 'alice-decoy' at idx %d, got ok=%v idx=%d username=%q", duressIdx, ok, idx, ks.Username)
	}
}

func TestUnlockSlotWrongPasswordNoMatch(t *testing.T) {
	c, realIdx, _, realKi, _, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	sealIdentity(t, c, realIdx, realKi, "alice")

	_, _, _, ok, err := UnlockSlot(c, "pf", "totally-wrong")
	if err != nil {
		t.Fatalf("UnlockSlot: %v", err)
	}
	if ok {
		t.Fatal("expected no match for a wrong password_identity")
	}

	_, _, _, ok, err = UnlockSlot(c, "wrong-file-password", "real-secret")
	if err != nil {
		t.Fatalf("UnlockSlot: %v", err)
	}
	if ok {
		t.Fatal("expected no match for a wrong password_file")
	}
}

func TestUnlockSlotDistinguishesMultipleRealIdentities(t *testing.T) {
	c, realIdx, _, realKi, _, pool, err := newSlotContainer("pf", "real1", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	sealIdentity(t, c, realIdx, realKi, "alice")

	idx2, ki2, _, err := c.AddRealIdentity("pf", "real2", pool)
	if err != nil {
		t.Fatalf("AddRealIdentity: %v", err)
	}
	sealIdentity(t, c, idx2, ki2, "bob")

	idx, _, ks, ok, err := UnlockSlot(c, "pf", "real1")
	if err != nil {
		t.Fatalf("UnlockSlot (real1): %v", err)
	}
	if !ok || idx != realIdx || ks.Username != "alice" {
		t.Fatalf("expected alice at idx %d, got ok=%v idx=%d ks=%v", realIdx, ok, idx, ks)
	}

	idx, _, ks, ok, err = UnlockSlot(c, "pf", "real2")
	if err != nil {
		t.Fatalf("UnlockSlot (real2): %v", err)
	}
	if !ok || idx != idx2 || ks.Username != "bob" {
		t.Fatalf("expected bob at idx %d, got ok=%v idx=%d ks=%v", idx2, ok, idx, ks)
	}
}

func TestUnlockSlotNeverOpensNoiseSlot(t *testing.T) {
	c, _, _, _, _, pool, err := newSlotContainer("pf", "real1", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if len(pool.Pending) != 1 {
		t.Fatalf("expected exactly 1 noise slot at birth, got %d", len(pool.Pending))
	}
	// No password known to any caller should ever match the untouched
	// noise slot.
	for _, candidate := range []string{"real1", "duress-secret", "", "guess"} {
		if _, ok := unwrapKi(c.Slots[pool.Pending[0]], "pf", candidate); ok {
			t.Fatalf("noise slot unexpectedly opened by %q", candidate)
		}
	}
}
