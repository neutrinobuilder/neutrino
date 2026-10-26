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

// Decoder reconstructs a payload from a stream of Symbol via peeling
// decoding (cascading belief propagation): a degree-1 symbol directly
// reveals a block; that block is then XORed out of every other pending
// symbol referencing it, potentially dropping others to degree 1 in a
// cascade, until all k blocks are known, or the symbols received so far
// aren't enough (in which case Add just accumulates, waiting for more
// symbols).
type Decoder struct {
	k, blockSize, totalLen int
	cdf                    []float64
	blocks                 [][]byte
	known                  int
	seen                   map[uint32]bool
	pending                map[uint32]*pendingSymbol
	waiting                map[int][]uint32 // block idx -> IDs of pending symbols still referencing it
}

type pendingSymbol struct {
	remaining map[int]bool
	data      []byte
}

// NewDecoder prepares a decoder for a transfer with k blocks of blockSize
// bytes, for an original payload of totalLen bytes (used only by Bytes to
// truncate the last block's zero padding, see Encoder). k and blockSize
// must be read from the received frame's header (outside this package),
// and must match exactly those used by NewEncoder on the sender side.
func NewDecoder(k, blockSize, totalLen int) *Decoder {
	return &Decoder{
		k: k, blockSize: blockSize, totalLen: totalLen,
		cdf:     degreeCDF(k),
		blocks:  make([][]byte, k),
		seen:    make(map[uint32]bool),
		pending: make(map[uint32]*pendingSymbol),
		waiting: make(map[int][]uint32),
	}
}

// Done reports whether all k blocks have been reconstructed, Bytes()
// returns a valid payload only at that point.
func (d *Decoder) Done() bool { return d.known == d.k }

// Progress returns (blocks known, total blocks), for a progress UI only,
// no effect on decoding.
func (d *Decoder) Progress() (known, total int) { return d.known, d.k }

// Add processes an incoming symbol. Idempotent with respect to
// already-seen IDs (an animated QR frame is read multiple times by the
// camera while it stays on screen: duplicates must be silently discarded,
// not treated as an error), safe to call repeatedly with the same Symbol.
func (d *Decoder) Add(sym Symbol) {
	if d.Done() || d.seen[sym.ID] {
		return
	}
	d.seen[sym.ID] = true

	indices := symbolIndices(sym.ID, d.k, d.cdf)
	data := append([]byte(nil), sym.Data...)
	remaining := make(map[int]bool, len(indices))
	for _, idx := range indices {
		if d.blocks[idx] != nil {
			xorInto(data, d.blocks[idx])
			continue
		}
		remaining[idx] = true
	}
	if len(remaining) == 0 {
		return // no new information (all blocks already known)
	}

	ps := &pendingSymbol{remaining: remaining, data: data}
	d.pending[sym.ID] = ps
	for idx := range remaining {
		d.waiting[idx] = append(d.waiting[idx], sym.ID)
	}
	if len(remaining) == 1 {
		d.resolve([]uint32{sym.ID})
	}
}

// resolve drains a queue of degree-1 symbols, propagating each block thus
// discovered to whoever still references it, can drop other symbols to
// degree 1, adding them to the same queue (avalanche/peeling).
func (d *Decoder) resolve(queue []uint32) {
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]

		cur, ok := d.pending[id]
		if !ok || len(cur.remaining) != 1 {
			continue // already resolved/drained in the meantime by another chain
		}
		var idx int
		for i := range cur.remaining {
			idx = i
		}
		d.blocks[idx] = cur.data
		d.known++
		delete(d.pending, id)

		waiters := d.waiting[idx]
		delete(d.waiting, idx)
		for _, wID := range waiters {
			w, ok := d.pending[wID]
			if !ok || !w.remaining[idx] {
				continue
			}
			delete(w.remaining, idx)
			xorInto(w.data, d.blocks[idx])
			switch len(w.remaining) {
			case 0:
				delete(d.pending, wID) // everything already known, no new information
			case 1:
				queue = append(queue, wID)
			}
		}

		if d.known == d.k {
			return
		}
	}
}

// Bytes returns the reconstructed payload, truncated to totalLen (removes
// the last block's zero padding), nil while Done() is still false.
func (d *Decoder) Bytes() []byte {
	if !d.Done() {
		return nil
	}
	out := make([]byte, 0, d.k*d.blockSize)
	for _, b := range d.blocks {
		out = append(out, b...)
	}
	if d.totalLen <= len(out) {
		out = out[:d.totalLen]
	}
	return out
}
