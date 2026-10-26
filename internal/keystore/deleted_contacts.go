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
	"bytes"
	"time"
)

// deletedContactIdx returns the index of the DeletedContacts row for
// identityPub, or -1 if none exists yet.
func (ks *Keystore) deletedContactIdx(identityPub []byte) int {
	for i, d := range ks.DeletedContacts {
		if bytes.Equal(d.IdentityPub, identityPub) {
			return i
		}
	}
	return -1
}

// HasDeletedContact reports whether identityPub already has a tombstone
// row, checked before accepting an incoming live contact during sync,
// so a stale copy from a sibling that hasn't learned of the deletion
// yet is never re-merged.
func (ks *Keystore) HasDeletedContact(identityPub []byte) bool {
	return ks.deletedContactIdx(identityPub) != -1
}

// RecordContactDeletion creates identityPub's tombstone row if one
// doesn't already exist yet, a no-op otherwise (deleting an
// already-deleted contact a second time changes nothing). Called from
// the real deletion path (EmptyMirroredContact's caller), never for
// duress's own mirrored contacts.
func (ks *Keystore) RecordContactDeletion(identityPub []byte) {
	if ks.HasDeletedContact(identityPub) {
		return
	}
	ks.DeletedContacts = append(ks.DeletedContacts, DeletedContact{
		IdentityPub: append([]byte(nil), identityPub...),
		DeletedAt:   time.Now(),
	})
}

// DeletedContactRow returns a copy of identityPub's tombstone row,
// ready to send to a sibling that just sent a stale live copy of that
// same contact, ok is false if no such row exists.
func (ks *Keystore) DeletedContactRow(identityPub []byte) (row DeletedContact, ok bool) {
	i := ks.deletedContactIdx(identityPub)
	if i == -1 {
		return DeletedContact{}, false
	}
	row = ks.DeletedContacts[i]
	row.ConfirmedSiblings = append([][]byte(nil), row.ConfirmedSiblings...)
	return row, true
}

// AdoptDeletedContact merges an incoming tombstone row (received from a
// sibling) into ks.DeletedContacts: creates the row if this identity
// never had it, or unions ConfirmedSiblings into the existing row
// otherwise. Returns true if the row was brand new here, the caller
// must then also delete any live contact matching incoming.IdentityPub.
func (ks *Keystore) AdoptDeletedContact(incoming DeletedContact) (isNew bool) {
	i := ks.deletedContactIdx(incoming.IdentityPub)
	if i == -1 {
		ks.DeletedContacts = append(ks.DeletedContacts, DeletedContact{
			IdentityPub:       append([]byte(nil), incoming.IdentityPub...),
			DeletedAt:         incoming.DeletedAt,
			ConfirmedSiblings: append([][]byte(nil), incoming.ConfirmedSiblings...),
		})
		return true
	}
	for _, dev := range incoming.ConfirmedSiblings {
		ks.addConfirmedSibling(i, dev)
	}
	return false
}

// ConfirmSiblingForDeletion adds deviceID to identityPub's tombstone row
// called once that sibling has acked having adopted the tombstone. A
// no-op if the row doesn't exist (shouldn't happen in correct usage:
// the row is always created before anyone could be asked to confirm
// it) or if deviceID is already recorded.
func (ks *Keystore) ConfirmSiblingForDeletion(identityPub, deviceID []byte) {
	i := ks.deletedContactIdx(identityPub)
	if i == -1 {
		return
	}
	ks.addConfirmedSibling(i, deviceID)
}

func (ks *Keystore) addConfirmedSibling(rowIdx int, deviceID []byte) {
	for _, existing := range ks.DeletedContacts[rowIdx].ConfirmedSiblings {
		if bytes.Equal(existing, deviceID) {
			return
		}
	}
	ks.DeletedContacts[rowIdx].ConfirmedSiblings = append(ks.DeletedContacts[rowIdx].ConfirmedSiblings, append([]byte(nil), deviceID...))
}
