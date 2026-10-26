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

// ObliterateOtherSlots overwrites every slot in c except keepIdx with
// fresh random bytes, field by field, each exactly as long as the
// field it replaces, the container's slot count and every slot's byte
// size stay identical, so the file looks structurally unchanged to
// anyone without a password. No slot's own password or K_i is ever
// needed for this: destroying a ciphertext requires no more than
// overwriting its bytes, never decrypting it first. The caller does not
// know, and does not need to know, which indices held a real identity
// versus pre-existing noise, every one of them is overwritten alike.
func ObliterateOtherSlots(c *slotContainer, keepIdx int) error {
	for i := range c.Slots {
		if i == keepIdx {
			continue
		}
		if err := randomizeSlot(&c.Slots[i]); err != nil {
			return err
		}
	}
	return nil
}

// ObliterateSlot overwrites exactly ONE slot (idx) with fresh random
// bytes, field by field, the inverse selection of ObliterateOtherSlots
// above, used where only one specific slot (not everything else) must
// be destroyed: a nuke trigger reached from an already-active session
// (/nukex, the "time" trigger, duress at the lock screen, remote_nuke on
// the target) must guarantee the triggering real identity's own slot
// never survives, but, unlike login-time duress obliteration, a
// deliberate "destroy everything else" panic action, must NOT blindly
// destroy every other slot in the same file: another real identity
// (a sibling identity) sharing the same keystore file is a legitimate,
// independently active identity, never implicated by this one's trigger
// (same scoping already applied to this trigger's sibling device-sync
// fan-out, which also covers only the identity that actually ran it).
func ObliterateSlot(c *slotContainer, idx int) error {
	if idx < 0 || idx >= len(c.Slots) {
		return errors.New(i18n.T("keystore.err_slot_index_invalid"))
	}
	return randomizeSlot(&c.Slots[idx])
}

func randomizeSlot(s *slotEntry) error {
	fields := []*[]byte{&s.Salt, &s.WrapNonce, &s.WrappedKi, &s.ContentNonce, &s.Content}
	for _, f := range fields {
		fresh := make([]byte, len(*f))
		if _, err := rand.Read(fresh); err != nil {
			return errors.New(i18n.T("keystore.err_slot_random", err))
		}
		*f = fresh
	}
	return nil
}
