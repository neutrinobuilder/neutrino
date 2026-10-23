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

// OverwriteAllContacts empties EVERY currently non-empty contact on u's
// own identity, in one batch — the in-place overwrite a nuke trigger
// uses on the identity it's destroying: the exact same treatment as a
// single normal contact deletion (EmptyMirroredContact), just applied
// to every contact at once instead of one at a time, with no special
// case for a nuke. Never removes any Contact
// slot (its index is recycled into ContactPendingIdx.Pending, same as a
// normal deletion) and never touches the identity's own keys/Username —
// only its Contacts. Each emptied contact's mirrored duress contact (if
// any) is emptied identically on duress's own side, preserving the same
// symmetric-shrink invariant as a normal deletion. Mutates u.Identity
// (and, in memory, the duress Keystore this returns) — the caller must
// pass duressIdx/duressKi/duressPlain to SaveWithDuress to persist both
// sides together; emptied==0 means nothing changed, nothing to save.
func (u *UnlockedSlot) OverwriteAllContacts() (duressIdx int, duressKi, duressPlain []byte, emptied int, err error) {
	for _, c := range u.Identity.Contacts {
		if len(c.IdentityPub) > 0 {
			emptied++
		}
	}
	if emptied == 0 {
		return 0, nil, nil, 0, nil
	}

	duressIdx, duressKi, duress, err := u.openDuressContent()
	if err != nil {
		return 0, nil, nil, 0, err
	}

	for i, c := range u.Identity.Contacts {
		if len(c.IdentityPub) == 0 {
			continue
		}
		u.Identity.Contacts[i] = Contact{}
		u.Identity.ContactPendingIdx.Pending = append(u.Identity.ContactPendingIdx.Pending, i)

		dIdx, found := u.Identity.ContactMirrorDuressIdx[i]
		if !found {
			continue
		}
		delete(u.Identity.ContactMirrorDuressIdx, i)
		if dIdx < 0 || dIdx >= len(duress.Contacts) {
			continue
		}
		duress.Contacts[dIdx] = Contact{}
		duress.ContactPendingIdx.Pending = append(duress.ContactPendingIdx.Pending, dIdx)
	}

	duressPlain, err = json.Marshal(duress)
	if err != nil {
		return 0, nil, nil, 0, errors.New(i18n.T("keystore.err_marshal", err))
	}
	return duressIdx, duressKi, duressPlain, emptied, nil
}
