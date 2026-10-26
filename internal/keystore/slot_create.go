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
	"sync"

	"neutrino/internal/i18n"
)

// CreateFile creates a brand new N-slot keystore file at path: real
// (already constructed, e.g. via New()) under passwordFile+
// realPasswordIdentity, duress (also already constructed, own chosen
// username included) under passwordFile+duressPasswordIdentity, and
// one noise placeholder. Fills in the slot-model bookkeeping on
// both (SlotPendingNoise, ContactPendingIdx, DuressAccess) before
// sealing them — the caller does not need to set these itself.
//
// Returns the resulting UnlockedSlot for real, ready for the caller to
// keep using this session exactly as if it had just been loaded from
// disk via LoadAndUnlock.
func CreateFile(path, passwordFile, realPasswordIdentity, duressPasswordIdentity string, real, duress *Keystore) (*UnlockedSlot, error) {
	c, realIdx, duressIdx, realKi, duressKi, pool, err := newSlotContainer(passwordFile, realPasswordIdentity, duressPasswordIdentity)
	if err != nil {
		return nil, err
	}

	if real.mu == nil {
		real.mu = &sync.Mutex{}
	}
	real.SlotPendingNoise = pool
	real.ContactPendingIdx = newGrowthPool(0)
	real.Contacts = append([]Contact{{}}, real.Contacts...)
	duressAccess, err := SealDuressAccess(realKi, duressKi)
	if err != nil {
		return nil, err
	}
	real.DuressAccess = duressAccess

	duress.IsDuress = true
	duress.ContactPendingIdx = newGrowthPool(0)
	duress.Contacts = append([]Contact{{}}, duress.Contacts...)
	noiseAccess, err := RandomDuressAccessField()
	if err != nil {
		return nil, err
	}
	duress.DuressAccess = noiseAccess
	duress.SlotPendingNoise = newGrowthPool(pool.Pending[len(pool.Pending)-1])

	realPlain, err := json.Marshal(real)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&c.Slots[realIdx], realKi, realPlain); err != nil {
		return nil, err
	}

	duressPlain, err := json.Marshal(duress)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&c.Slots[duressIdx], duressKi, duressPlain); err != nil {
		return nil, err
	}

	if err := WriteSlotContainer(path, c); err != nil {
		return nil, err
	}
	return &UnlockedSlot{Container: c, Idx: realIdx, Ki: realKi, Identity: real, PasswordFile: passwordFile, PasswordIdentity: realPasswordIdentity}, nil
}
