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

// growthPool tracks a set of not-yet-assigned indices that grows in
// batches, doubling in size each time the current batch is fully
// consumed: batch sizes follow 1→2→4→8→16... Used both for the
// file-level identity slots (slot_container.go) and for each identity's
// own Contacts list (slot_mirror_contact.go).
type growthPool struct {
	Pending       []int `json:"pending,omitempty"`
	NextBatchSize int   `json:"next_batch_size,omitempty"`
}

// newGrowthPool creates the pool at birth: one pending index (firstIdx)
// — the NEXT batch, once this single one is consumed, will have size
// 2.
func newGrowthPool(firstIdx int) growthPool {
	return growthPool{Pending: []int{firstIdx}, NextBatchSize: 2}
}

// consume takes the next pending index. If this exhausts the pool, it
// immediately creates NextBatchSize fresh indices (continuing from
// currentLen, the owning list's length BEFORE this call) and doubles
// NextBatchSize for the batch after this one. newLen is the length the
// caller's own list must grow to — equal to currentLen when no new
// batch was created this time. ok is false only if the pool was never
// initialized (defensive — correct usage never actually runs dry,
// since a saturating consume always immediately refills within the
// same call).
func (p *growthPool) consume(currentLen int) (consumedIdx, newLen int, ok bool) {
	if len(p.Pending) == 0 {
		return 0, 0, false
	}
	consumedIdx = p.Pending[0]
	p.Pending = append([]int{}, p.Pending[1:]...)
	newLen = currentLen
	if len(p.Pending) == 0 {
		batch := p.NextBatchSize
		newIndices := make([]int, batch)
		for i := range newIndices {
			newIndices[i] = currentLen + i
		}
		p.Pending = newIndices
		newLen = currentLen + batch
		p.NextBatchSize *= 2
	}
	return consumedIdx, newLen, true
}
