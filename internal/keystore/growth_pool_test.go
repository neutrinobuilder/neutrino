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

func TestGrowthPoolBatchSizeSequence(t *testing.T) {
	pool := newGrowthPool(0)
	currentLen := 1 // one pending index already occupies slot 0

	// Batch 1 (size 1): consuming it saturates immediately, creating
	// batch 2 (size 2).
	idx, newLen, ok := pool.consume(currentLen)
	if !ok || idx != 0 {
		t.Fatalf("expected to consume index 0, got idx=%d ok=%v", idx, ok)
	}
	if newLen != 3 || len(pool.Pending) != 2 {
		t.Fatalf("expected batch of 2 after first saturation (len=3, pending=2), got len=%d pending=%v", newLen, pool.Pending)
	}
	currentLen = newLen

	// Batch 2 (size 2): first consume does NOT saturate yet.
	idx, newLen, ok = pool.consume(currentLen)
	if !ok {
		t.Fatal("consume failed")
	}
	if newLen != currentLen {
		t.Fatalf("expected no growth mid-batch, got newLen=%d currentLen=%d", newLen, currentLen)
	}
	if len(pool.Pending) != 1 {
		t.Fatalf("expected 1 pending left mid-batch, got %v", pool.Pending)
	}

	// Second consume of batch 2 saturates it, creating batch 3 (size 4).
	idx, newLen, ok = pool.consume(currentLen)
	if !ok {
		t.Fatal("consume failed")
	}
	if newLen != currentLen+4 {
		t.Fatalf("expected batch of 4 after second saturation, got newLen=%d currentLen=%d", newLen, currentLen)
	}
	if len(pool.Pending) != 4 {
		t.Fatalf("expected 4 pending after 2nd saturation, got %v", pool.Pending)
	}
	currentLen = newLen
	_ = idx

	// Consume all 4 of batch 3: the first 3 must not grow anything, the
	// 4th must saturate into a batch of 8.
	for i := range 3 {
		_, gotLen, ok := pool.consume(currentLen)
		if !ok {
			t.Fatal("consume failed")
		}
		if gotLen != currentLen {
			t.Fatalf("expected no growth on consume %d of batch 3, got newLen=%d", i, gotLen)
		}
	}
	_, newLen, ok = pool.consume(currentLen)
	if !ok {
		t.Fatal("consume failed")
	}
	if newLen != currentLen+8 {
		t.Fatalf("expected batch of 8 after 3rd saturation, got newLen=%d currentLen=%d", newLen, currentLen)
	}
	if len(pool.Pending) != 8 {
		t.Fatalf("expected 8 pending after 3rd saturation, got %v", pool.Pending)
	}
}

func TestGrowthPoolConsumedIndicesNeverRepeat(t *testing.T) {
	pool := newGrowthPool(0)
	currentLen := 1
	seen := map[int]bool{}
	for i := range 20 {
		idx, newLen, ok := pool.consume(currentLen)
		if !ok {
			t.Fatalf("consume failed at iteration %d", i)
		}
		if seen[idx] {
			t.Fatalf("index %d consumed twice", idx)
		}
		seen[idx] = true
		currentLen = newLen
	}
}

func TestGrowthPoolEmptyIsDefensiveFailure(t *testing.T) {
	pool := growthPool{}
	if _, _, ok := pool.consume(0); ok {
		t.Fatal("expected consume on an uninitialized pool to fail")
	}
}
