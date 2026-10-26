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

// Package fountain implements pure-Go Luby Transform (LT) codes — an
// encoder and peeling decoder for fountain coding, meant for animated QR
// optical transfer: the sender generates a potentially infinite stream of
// encoded symbols, shown in a loop as animated QR codes; the receiver
// reconstructs the message by collecting ~K·1.1-1.2 distinct symbols in
// ANY order, tolerating lost, duplicated, or out-of-order frames — no
// explicit retransmission needed.
//
// Not cryptographic: the integrity of the reconstructed content remains
// the responsibility of a higher layer (message signature), no
// verification happens here.
package fountain

import "errors"

// maxBlocks caps k (number of source blocks per transfer) — beyond this
// threshold, the cost of the linear search in sampleDegree and of the
// decoder's "waiting" map would grow with no real benefit: a larger
// payload should be split upstream into more transfers, not into
// increasingly many blocks within the same transfer.
const maxBlocks = 1 << 16

// Symbol is an encoded symbol, ready for the wire (e.g. a QR frame's
// payload) — ID identifies both the symbol itself (to discard duplicates)
// and, together with k, the degree and the set of source blocks that
// compose it.
type Symbol struct {
	ID   uint32
	Data []byte
}

// Encoder generates a stream of Symbol from a fixed payload, split into K
// blocks of BlockSize bytes (the last one zero-padded, never transmitted
// beyond TotalLen — the caller already knows it and discards it
// downstream).
type Encoder struct {
	blocks [][]byte
	cdf    []float64
}

// NewEncoder splits data into blockSize-byte blocks (the last one,
// possibly partial, is extended with zeros). blockSize must be chosen by
// the caller based on a QR frame's budget — Encoder has no visibility into
// QR codes/frames.
func NewEncoder(data []byte, blockSize int) (*Encoder, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid blockSize")
	}
	k := (len(data) + blockSize - 1) / blockSize
	if k == 0 {
		k = 1 // empty payload: a single all-zero block, K() consistent with NewDecoder
	}
	if k > maxBlocks {
		return nil, errors.New("payload too large for a single fountain transfer")
	}
	blocks := make([][]byte, k)
	for i := 0; i < k; i++ {
		start := i * blockSize
		b := make([]byte, blockSize)
		if start < len(data) {
			copy(b, data[start:min(start+blockSize, len(data))])
		}
		blocks[i] = b
	}
	return &Encoder{blocks: blocks, cdf: degreeCDF(k)}, nil
}

// K returns the number of source blocks — must be communicated to the
// receiver outside this package (e.g. in the QR frame header), together
// with BlockSize() and the original payload's real length.
func (e *Encoder) K() int { return len(e.blocks) }

// BlockSize returns a block's size (the one passed to NewEncoder,
// unchanged for the whole transfer).
func (e *Encoder) BlockSize() int { return len(e.blocks[0]) }

// Next generates the encoded symbol for id — the caller iterates over IDs
// (sequential or random, as long as they aren't repeated within the same
// transfer) to produce a stream of arbitrary length; there is no
// "exhausted" state, different ids always produce new valid symbols.
func (e *Encoder) Next(id uint32) Symbol {
	indices := symbolIndices(id, len(e.blocks), e.cdf)
	out := make([]byte, len(e.blocks[0]))
	for _, idx := range indices {
		xorInto(out, e.blocks[idx])
	}
	return Symbol{ID: id, Data: out}
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
