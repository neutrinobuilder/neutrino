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

package fountain

import (
	"bytes"
	"math/rand"
	"testing"
)

// decodeWithSymbols simulates the symbols->decoder flow without going
// through a real QR channel — used by every round-trip test below.
func decodeWithSymbols(t *testing.T, enc *Encoder, totalLen int, symbolIDs []uint32) []byte {
	t.Helper()
	dec := NewDecoder(enc.K(), enc.BlockSize(), totalLen)
	for _, id := range symbolIDs {
		dec.Add(enc.Next(id))
		if dec.Done() {
			break
		}
	}
	if !dec.Done() {
		t.Fatalf("decoder not complete after %d symbols (k=%d)", len(symbolIDs), enc.K())
	}
	return dec.Bytes()
}

// TestRoundTripSequentialIDs covers the simplest case: sequential symbols,
// no loss — must always complete with a number of symbols not much larger
// than k (typical overhead ~10-20%).
func TestRoundTripSequentialIDs(t *testing.T) {
	sizes := []int{1, 17, 100, 1000, 65536}
	for _, size := range sizes {
		payload := make([]byte, size)
		if _, err := rand.New(rand.NewSource(int64(size))).Read(payload); err != nil {
			t.Fatalf("size=%d: generating the payload: %v", size, err)
		}
		enc, err := NewEncoder(payload, 64)
		if err != nil {
			t.Fatalf("size=%d: NewEncoder: %v", size, err)
		}

		maxSymbols := enc.K()*2 + 50 // ample margin, the test checks "it finishes", not exact overhead
		ids := make([]uint32, maxSymbols)
		for i := range ids {
			ids[i] = uint32(i)
		}
		got := decodeWithSymbols(t, enc, size, ids)
		if !bytes.Equal(got, payload) {
			t.Fatalf("size=%d: round-trip corrupted", size)
		}
	}
}

// TestRoundTripRandomIDsWithLossAndDuplicates is the realistic case for an
// optical channel: random IDs (non-sequential — a sender might generate
// them this way to avoid coordinating shared state), with duplicates (the
// same frame read multiple times) and simulated "loss" (a subset of
// symbols never generated/delivered).
func TestRoundTripRandomIDsWithLossAndDuplicates(t *testing.T) {
	payload := bytes.Repeat([]byte("neutrino fountain "), 300) // ~5.4KB
	enc, err := NewEncoder(payload, 96)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}

	r := rand.New(rand.NewSource(42))
	dec := NewDecoder(enc.K(), enc.BlockSize(), len(payload))
	const maxAttempts = 20000
	for i := 0; i < maxAttempts && !dec.Done(); i++ {
		id := uint32(r.Int31())
		sym := enc.Next(id)
		dec.Add(sym)
		if r.Intn(3) == 0 {
			dec.Add(sym) // deliberate duplicate, same ID
		}
	}
	if !dec.Done() {
		t.Fatalf("decoder not complete after %d random symbols (k=%d)", maxAttempts, enc.K())
	}
	if got := dec.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("round-trip corrupted with random/duplicate IDs")
	}
}

// TestDecodeStallsWithTooFewSymbols checks that the decoder does NOT
// falsely report Done() with too few symbols — no false positives.
func TestDecodeStallsWithTooFewSymbols(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 5000)
	enc, err := NewEncoder(payload, 50) // k=100
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec := NewDecoder(enc.K(), enc.BlockSize(), len(payload))
	dec.Add(enc.Next(1))
	dec.Add(enc.Next(2))
	if dec.Done() {
		t.Fatalf("Done() = true with only 2 symbols out of k=%d, want false", enc.K())
	}
	if dec.Bytes() != nil {
		t.Fatalf("Bytes() non-nil prima di Done()")
	}
}

// TestSingleBlockAndEmptyPayload covers the two edge cases: a payload
// exactly filling one block (k=1, where the robust soliton distribution
// degenerates to a single possible degree) and an empty payload.
func TestSingleBlockAndEmptyPayload(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("ciao"),
		make([]byte, 32), // exactly one block
	}
	for _, payload := range cases {
		enc, err := NewEncoder(payload, 32)
		if err != nil {
			t.Fatalf("NewEncoder(%d byte): %v", len(payload), err)
		}
		if enc.K() != 1 {
			t.Fatalf("K() = %d, want 1 for a %d-byte payload with blockSize=32", enc.K(), len(payload))
		}
		dec := NewDecoder(enc.K(), enc.BlockSize(), len(payload))
		dec.Add(enc.Next(7))
		if !dec.Done() {
			t.Fatalf("decoder not complete with k=1 after a single symbol")
		}
		if got := dec.Bytes(); !bytes.Equal(got, payload) {
			t.Fatalf("round-trip corrupted for a %d-byte payload: got %q, want %q", len(payload), got, payload)
		}
	}
}

// TestOverheadStaysReasonable empirically measures how many symbols are
// needed to complete relative to k, on sequential IDs with no loss —
// guards against a future change to the distribution silently degrading
// overhead. A tolerance of up to 1.5×k avoids making the test fragile on a
// single seed, while a much worse systematic overhead would indicate a
// real problem in the distribution.
func TestOverheadStaysReasonable(t *testing.T) {
	payload := bytes.Repeat([]byte("overhead-check-"), 2000) // large k, more stable statistics
	enc, err := NewEncoder(payload, 64)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	dec := NewDecoder(enc.K(), enc.BlockSize(), len(payload))
	var used int
	for used = 0; !dec.Done(); used++ {
		dec.Add(enc.Next(uint32(used)))
	}
	overhead := float64(used) / float64(enc.K())
	if overhead > 1.5 {
		t.Fatalf("overhead = %.2f×k (used %d symbols for k=%d), want <= 1.5×k", overhead, used, enc.K())
	}
	t.Logf("k=%d, symbols used=%d, overhead=%.3f×k", enc.K(), used, overhead)
}

// TestSymbolIndicesDeterministic checks the property the whole protocol
// relies on: same ID + same k => same set of indices, always — this is
// what lets encoder and decoder never exchange the degree or the indices,
// only the ID.
func TestSymbolIndicesDeterministic(t *testing.T) {
	cdf := degreeCDF(500)
	for _, id := range []uint32{0, 1, 42, 1 << 20, 0xFFFFFFFF} {
		a := symbolIndices(id, 500, cdf)
		b := symbolIndices(id, 500, cdf)
		if len(a) != len(b) {
			t.Fatalf("id=%d: different lengths between two calls: %d vs %d", id, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("id=%d: index %d differs between two calls: %d vs %d", id, i, a[i], b[i])
			}
		}
	}
}
