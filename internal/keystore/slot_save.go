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

// UnlockedSlot bundles everything a session needs to later reseal
// exactly the slots it has touched, leaving every other slot, other
// real identities never unlocked this session, every noise placeholder
// untouched byte for byte. Container is the whole file as read from
// disk: SaveSlot/SaveWithDuress write it back in full, but only after
// mutating this one identity's own slot (and, when applicable,
// duress's).
type UnlockedSlot struct {
	Container *slotContainer
	Idx       int
	Ki        []byte
	Identity  *Keystore
	// PasswordFile/PasswordIdentity are retained for the lifetime of
	// the session because later operations (AddRealIdentity,
	// RewrapOwnSlot, VerifyPasswordIdentity) need to wrap a slot's K_i
	// again.
	PasswordFile     string
	PasswordIdentity string
}

// LoadAndUnlock reads path's whole container and unlocks one slot from
// it in a single call. ok is false (err nil) when no slot answered to
// this password combination, the same non-distinguishable outcome as
// UnlockSlot.
func LoadAndUnlock(path, passwordFile, passwordIdentity string) (*UnlockedSlot, bool, error) {
	c, err := ReadSlotContainer(path)
	if err != nil {
		return nil, false, err
	}
	idx, ki, ks, ok, err := UnlockSlot(c, passwordFile, passwordIdentity)
	if err != nil || !ok {
		return nil, ok, err
	}
	return &UnlockedSlot{Container: c, Idx: idx, Ki: ki, Identity: ks, PasswordFile: passwordFile, PasswordIdentity: passwordIdentity}, true, nil
}

// SaveSlot reseals u.Identity's current content into its own slot and
// writes the whole container back to path. Every other slot, duress's
// included, passes through unchanged: this call never needs, and
// never has, their password or K_i. Runs entirely under the identity's
// mu, so concurrent saves never interleave and the file always ends up
// holding the latest one.
func (u *UnlockedSlot) SaveSlot(path string) error {
	u.Identity.mu.Lock()
	defer u.Identity.mu.Unlock()
	u.Identity.ensureRelRevocations()
	plain, err := json.Marshal(u.Identity)
	if err != nil {
		return errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&u.Container.Slots[u.Idx], u.Ki, plain); err != nil {
		return err
	}
	return WriteSlotContainer(path, u.Container)
}

// SaveWithDuress is SaveSlot plus resealing duress's own slot content
// with duressPlain, under duressKi (obtained via DuressAccess, no
// password needed), used whenever this session's operation also wrote
// into duress's mirrored content.
func (u *UnlockedSlot) SaveWithDuress(path string, duressIdx int, duressKi, duressPlain []byte) error {
	u.Identity.mu.Lock()
	defer u.Identity.mu.Unlock()
	u.Identity.ensureRelRevocations()
	plain, err := json.Marshal(u.Identity)
	if err != nil {
		return errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&u.Container.Slots[u.Idx], u.Ki, plain); err != nil {
		return err
	}
	if err := sealSlotContent(&u.Container.Slots[duressIdx], duressKi, duressPlain); err != nil {
		return err
	}
	return WriteSlotContainer(path, u.Container)
}
