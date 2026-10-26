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

import "testing"

func TestDuressAccessRoundTrip(t *testing.T) {
	ownKi, err := newSlotKi()
	if err != nil {
		t.Fatalf("newSlotKi (own): %v", err)
	}
	duressKi, err := newSlotKi()
	if err != nil {
		t.Fatalf("newSlotKi (duress): %v", err)
	}

	field, err := SealDuressAccess(ownKi, duressKi)
	if err != nil {
		t.Fatalf("SealDuressAccess: %v", err)
	}
	got, err := OpenDuressAccess(ownKi, field)
	if err != nil {
		t.Fatalf("OpenDuressAccess: %v", err)
	}
	if string(got) != string(duressKi) {
		t.Fatal("recovered K_i_duress does not match the original")
	}
}

func TestDuressAccessWrongOwnKiFails(t *testing.T) {
	ownKi, _ := newSlotKi()
	otherKi, _ := newSlotKi()
	duressKi, _ := newSlotKi()

	field, err := SealDuressAccess(ownKi, duressKi)
	if err != nil {
		t.Fatalf("SealDuressAccess: %v", err)
	}
	if _, err := OpenDuressAccess(otherKi, field); err == nil {
		t.Fatal("expected OpenDuressAccess to fail with a different identity's K_i")
	}
}

func TestRandomDuressAccessFieldMatchesRealShape(t *testing.T) {
	ownKi, _ := newSlotKi()
	duressKi, _ := newSlotKi()

	real, err := SealDuressAccess(ownKi, duressKi)
	if err != nil {
		t.Fatalf("SealDuressAccess: %v", err)
	}
	noise, err := RandomDuressAccessField()
	if err != nil {
		t.Fatalf("RandomDuressAccessField: %v", err)
	}
	if len(real.Nonce) != len(noise.Nonce) || len(real.Wrapped) != len(noise.Wrapped) {
		t.Fatalf("noise field shape differs from a real field: real nonce=%d wrapped=%d, noise nonce=%d wrapped=%d",
			len(real.Nonce), len(real.Wrapped), len(noise.Nonce), len(noise.Wrapped))
	}
}

func TestRandomDuressAccessFieldNotOpenable(t *testing.T) {
	ownKi, _ := newSlotKi()
	noise, err := RandomDuressAccessField()
	if err != nil {
		t.Fatalf("RandomDuressAccessField: %v", err)
	}
	if _, err := OpenDuressAccess(ownKi, noise); err == nil {
		t.Fatal("expected a random noise field to never successfully open")
	}
}
