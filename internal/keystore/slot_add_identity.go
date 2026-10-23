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
	"errors"

	"neutrino/internal/i18n"
)

// AddRealIdentity adds a brand-new real identity to the same file,
// sharing u's password_file, under newPasswordIdentity — the same
// doubling growth already used for every other real identity (see
// slot_container.go). newIdentity is the already-constructed Keystore
// content (username, keys, etc.); this call fills in its slot-model
// bookkeeping (SlotPendingNoise, ContactPendingIdx, DuressAccess) and
// seals it into u's container, in memory — the caller still must call
// u.SaveSlot(path) afterward to persist both this change and the new
// identity's own slot together.
//
// Does not touch duress's content: duress's own SlotPendingNoise is
// decorative, never the real file-level pending list.
func (u *UnlockedSlot) AddRealIdentity(newPasswordIdentity string, newIdentity *Keystore) (idx int, newKi []byte, err error) {
	idx, newKi, updatedPool, err := u.Container.AddRealIdentity(u.PasswordFile, newPasswordIdentity, u.Identity.SlotPendingNoise)
	if err != nil {
		return 0, nil, err
	}
	u.Identity.SlotPendingNoise = updatedPool

	duressKi, err := OpenDuressAccess(u.Ki, u.Identity.DuressAccess)
	if err != nil {
		return 0, nil, err
	}
	duressAccess, err := SealDuressAccess(newKi, duressKi)
	if err != nil {
		return 0, nil, err
	}
	newIdentity.DuressAccess = duressAccess
	newIdentity.ContactPendingIdx = newGrowthPool(0)
	newIdentity.Contacts = append([]Contact{{}}, newIdentity.Contacts...)
	// The new identity shares the SAME file-level pending-noise
	// bookkeeping as the one that created it from this point on (one
	// shared pool, see slot_container.go) — copied, not aliased, so
	// each identity's own future consumes never touch the other's
	// slice.
	newIdentity.SlotPendingNoise = growthPool{
		Pending:       append([]int{}, updatedPool.Pending...),
		NextBatchSize: updatedPool.NextBatchSize,
	}

	plain, err := json.Marshal(newIdentity)
	if err != nil {
		return 0, nil, errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&u.Container.Slots[idx], newKi, plain); err != nil {
		return 0, nil, err
	}
	return idx, newKi, nil
}
