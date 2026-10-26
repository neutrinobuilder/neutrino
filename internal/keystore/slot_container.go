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
	"errors"

	"neutrino/internal/i18n"
)

// slotContainer is the on-disk N-slot keystore file: every identity
// (real or the single shared duress) occupies one independent
// slotEntry, plus any number of not-yet-assigned noise placeholders of
// the identical shape (see slots.go). No file-level flag marks which
// indices are "live". The list only grows: AddRealIdentity never
// removes a slot, only appends.
//
// Bookkeeping of which indices are still unassigned noise is not part
// of this type, it is tracked by the caller and mirrored inside every
// REAL identity's own encrypted content. The shared duress identity
// carries the same field shape but filled with random noise instead of
// the real list.
type slotContainer struct {
	Slots []slotEntry
}

// newSlotContainer creates the file at birth: one real identity slot,
// the shared duress slot, and a single noise placeholder. realKi/duressKi
// are the two live slots' raw content keys, returned so the caller can
// seal their actual JSON payload, newSlotContainer only prepares empty
// slots, it never writes identity content. pool is the growth pool the
// caller must store on the real identity's own content, index 2 (the
// noise placeholder) is its one starting pending entry.
func newSlotContainer(passwordFile, realPasswordIdentity, duressPasswordIdentity string) (c *slotContainer, realIdx, duressIdx int, realKi, duressKi []byte, pool growthPool, err error) {
	realKi, err = newSlotKi()
	if err != nil {
		return nil, 0, 0, nil, nil, growthPool{}, err
	}
	realSlot, err := newSlot(realKi, passwordFile, realPasswordIdentity)
	if err != nil {
		return nil, 0, 0, nil, nil, growthPool{}, err
	}
	if passwordIdentityCollides([]slotEntry{realSlot}, passwordFile, duressPasswordIdentity) {
		return nil, 0, 0, nil, nil, growthPool{}, errors.New(i18n.T("keystore.err_identity_password_collision"))
	}
	duressKi, err = newSlotKi()
	if err != nil {
		return nil, 0, 0, nil, nil, growthPool{}, err
	}
	duressSlot, err := newSlot(duressKi, passwordFile, duressPasswordIdentity)
	if err != nil {
		return nil, 0, 0, nil, nil, growthPool{}, err
	}
	noiseSlot, err := newNoiseSlot()
	if err != nil {
		return nil, 0, 0, nil, nil, growthPool{}, err
	}
	c = &slotContainer{Slots: []slotEntry{realSlot, duressSlot, noiseSlot}}
	return c, 0, 1, realKi, duressKi, newGrowthPool(2), nil
}

// AddRealIdentity promotes one pending noise slot into a brand-new real
// identity under passwordIdentity, overwriting that index with an
// entirely fresh slot. How many fresh noise slots take its place
// follows growthPool.consume's batch rule.
//
// pool is the caller's current growth pool (mirrored inside every real
// identity's own content); updatedPool is what the caller must then
// store back.
func (c *slotContainer) AddRealIdentity(passwordFile, passwordIdentity string, pool growthPool) (newIdx int, ki []byte, updatedPool growthPool, err error) {
	if passwordIdentityCollides(c.Slots, passwordFile, passwordIdentity) {
		return 0, nil, growthPool{}, errors.New(i18n.T("keystore.err_identity_password_collision"))
	}

	currentLen := len(c.Slots)
	idx, newLen, ok := pool.consume(currentLen)
	if !ok {
		return 0, nil, growthPool{}, errors.New(i18n.T("keystore.err_no_noise_slot"))
	}
	for len(c.Slots) < newLen {
		n, err := newNoiseSlot()
		if err != nil {
			return 0, nil, growthPool{}, err
		}
		c.Slots = append(c.Slots, n)
	}

	ki, err = newSlotKi()
	if err != nil {
		return 0, nil, growthPool{}, err
	}
	slot, err := newSlot(ki, passwordFile, passwordIdentity)
	if err != nil {
		return 0, nil, growthPool{}, err
	}
	c.Slots[idx] = slot

	return idx, ki, pool, nil
}
