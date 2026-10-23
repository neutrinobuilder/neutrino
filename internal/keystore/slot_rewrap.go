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
	"crypto/rand"
	"errors"

	"neutrino/internal/i18n"
)

// RewrapSlot changes slot idx's password combination without touching
// its content. ki is the slot's already-known raw content key — the
// caller is responsible for checking newPasswordIdentity doesn't
// collide with any other slot (passwordIdentityCollides) before
// calling this.
func RewrapSlot(c *slotContainer, idx int, ki []byte, newPasswordFile, newPasswordIdentity string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return errors.New(i18n.T("keystore.err_salt", err))
	}
	wrapNonce := make([]byte, nonceLen)
	if _, err := rand.Read(wrapNonce); err != nil {
		return errors.New(i18n.T("keystore.err_nonce", err))
	}
	wrappedKi, err := aesgcmEncrypt(deriveSlotWrapKey(newPasswordFile, newPasswordIdentity, salt), wrapNonce, ki)
	if err != nil {
		return err
	}
	c.Slots[idx].Salt = salt
	c.Slots[idx].WrapNonce = wrapNonce
	c.Slots[idx].WrappedKi = wrappedKi
	return nil
}

// RewrapOwnSlot is RewrapSlot applied to u's own slot, and updates u's
// cached PasswordFile/PasswordIdentity to match — the common case (a
// session changing its own password).
func (u *UnlockedSlot) RewrapOwnSlot(newPasswordFile, newPasswordIdentity string) error {
	if err := RewrapSlot(u.Container, u.Idx, u.Ki, newPasswordFile, newPasswordIdentity); err != nil {
		return err
	}
	u.PasswordFile = newPasswordFile
	u.PasswordIdentity = newPasswordIdentity
	return nil
}

// VerifyPasswordIdentity reports whether candidate (combined with u's
// own, already-known password_file) still opens u's own slot — used to
// confirm the "old password" step of a password change without
// needing to re-read the file from disk.
func (u *UnlockedSlot) VerifyPasswordIdentity(candidate string) bool {
	_, ok := unwrapKi(u.Container.Slots[u.Idx], u.PasswordFile, candidate)
	return ok
}

// PasswordIdentityAvailable reports whether candidate (combined with
// u's own password_file) is still free to assign to u's own slot — it
// doesn't already open ANY slot in the container (see
// passwordIdentityCollides, which login would otherwise find
// ambiguous).
func (u *UnlockedSlot) PasswordIdentityAvailable(candidate string) bool {
	return !passwordIdentityCollides(u.Container.Slots, u.PasswordFile, candidate)
}
