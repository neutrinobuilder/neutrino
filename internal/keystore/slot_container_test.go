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

func TestNewSlotContainerBirth(t *testing.T) {
	c, realIdx, duressIdx, realKi, duressKi, pool, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if len(c.Slots) != 3 {
		t.Fatalf("expected 3 slots at birth, got %d", len(c.Slots))
	}
	if realIdx != 0 || duressIdx != 1 {
		t.Fatalf("expected real=0 duress=1, got real=%d duress=%d", realIdx, duressIdx)
	}
	if len(pool.Pending) != 1 || pool.Pending[0] != 2 || pool.NextBatchSize != 2 {
		t.Fatalf("expected exactly one pending noise slot at index 2 with next batch size 2, got %+v", pool)
	}

	gotRealKi, ok := unwrapKi(c.Slots[realIdx], "pf", "real-secret")
	if !ok || string(gotRealKi) != string(realKi) {
		t.Fatal("real slot does not unwrap to the returned K_i")
	}
	gotDuressKi, ok := unwrapKi(c.Slots[duressIdx], "pf", "duress-secret")
	if !ok || string(gotDuressKi) != string(duressKi) {
		t.Fatal("duress slot does not unwrap to the returned K_i")
	}
	// Cross-checks: the real password must not open duress's slot and
	// vice versa.
	if _, ok := unwrapKi(c.Slots[duressIdx], "pf", "real-secret"); ok {
		t.Fatal("real password unexpectedly opened the duress slot")
	}
	if _, ok := unwrapKi(c.Slots[realIdx], "pf", "duress-secret"); ok {
		t.Fatal("duress password unexpectedly opened the real slot")
	}
}

func TestNewSlotContainerRejectsDuressSameAsReal(t *testing.T) {
	if _, _, _, _, _, _, err := newSlotContainer("pf", "same-secret", "same-secret"); err == nil {
		t.Fatal("expected error when duress password_identity equals the real one")
	}
}

// TestAddRealIdentityBatchSaturationGrowth verifies the batch-
// saturation doubling rule end to end at the slotContainer level (see
// growth_pool.go): a new
// batch of noise slots — DOUBLE the size of the one just exhausted —
// is created only once the CURRENT batch is completely consumed, not
// on every single AddRealIdentity call.
func TestAddRealIdentityBatchSaturationGrowth(t *testing.T) {
	c, _, _, _, _, pool, err := newSlotContainer("pf", "real1", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if len(c.Slots) != 3 || len(pool.Pending) != 1 {
		t.Fatalf("unexpected birth state: %d slots, %d pending", len(c.Slots), len(pool.Pending))
	}

	// Batch 1 (size 1) is exhausted by this very first call: it must
	// saturate immediately, creating batch 2 (size 2).
	idx2, ki2, pool, err := c.AddRealIdentity("pf", "real2", pool)
	if err != nil {
		t.Fatalf("AddRealIdentity (2nd identity): %v", err)
	}
	if idx2 != 2 {
		t.Fatalf("expected the 2nd real identity to consume index 2, got %d", idx2)
	}
	if len(c.Slots) != 5 {
		t.Fatalf("expected 5 slots after batch-2 creation (3 + 2 noise), got %d", len(c.Slots))
	}
	if len(pool.Pending) != 2 {
		t.Fatalf("expected 2 pending noise slots (batch 2), got %d: %v", len(pool.Pending), pool.Pending)
	}
	if got, ok := unwrapKi(c.Slots[idx2], "pf", "real2"); !ok || string(got) != string(ki2) {
		t.Fatal("newly promoted slot does not unwrap with its own password")
	}

	// Consuming the FIRST of batch 2's two slots must NOT grow
	// anything — the batch isn't saturated yet.
	idx3, _, pool, err := c.AddRealIdentity("pf", "real3", pool)
	if err != nil {
		t.Fatalf("AddRealIdentity (3rd identity): %v", err)
	}
	if len(c.Slots) != 5 {
		t.Fatalf("expected NO growth mid-batch, still 5 slots, got %d", len(c.Slots))
	}
	if len(pool.Pending) != 1 {
		t.Fatalf("expected 1 pending noise slot left in batch 2, got %d: %v", len(pool.Pending), pool.Pending)
	}
	if idx3 == idx2 {
		t.Fatal("3rd identity reused the same index as the 2nd")
	}

	// Consuming the LAST of batch 2's two slots saturates it, creating
	// batch 3 (size 4, double of batch 2).
	idx4, _, pool, err := c.AddRealIdentity("pf", "real4", pool)
	if err != nil {
		t.Fatalf("AddRealIdentity (4th identity): %v", err)
	}
	if len(c.Slots) != 9 {
		t.Fatalf("expected 9 slots after batch-4 creation (5 + 4 noise), got %d", len(c.Slots))
	}
	if len(pool.Pending) != 4 {
		t.Fatalf("expected 4 pending noise slots (batch 3), got %d: %v", len(pool.Pending), pool.Pending)
	}
	if idx4 == idx2 || idx4 == idx3 {
		t.Fatal("4th identity reused a previous index")
	}

	// All identities plus duress must remain independently openable
	// after the growth.
	if _, ok := unwrapKi(c.Slots[0], "pf", "real1"); !ok {
		t.Fatal("original real identity no longer opens after growth")
	}
	if _, ok := unwrapKi(c.Slots[1], "pf", "duress-secret"); !ok {
		t.Fatal("duress identity no longer opens after growth")
	}
}

func TestAddRealIdentityRejectsPasswordCollision(t *testing.T) {
	c, _, _, _, _, pool, err := newSlotContainer("pf", "real1", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	if _, _, _, err := c.AddRealIdentity("pf", "real1", pool); err == nil {
		t.Fatal("expected collision error when reusing the existing real identity's password")
	}
	if _, _, _, err := c.AddRealIdentity("pf", "duress-secret", pool); err == nil {
		t.Fatal("expected collision error when reusing duress's password")
	}
}
