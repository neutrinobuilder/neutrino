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

// openDuressContent locates and decrypts the shared duress identity's
// own content using K_i_duress — obtained from u's own DuressAccess
// field, no password needed (see
// duress_access.go). Returns duress's slot index too, since the
// caller will need it to reseal that same slot afterward (see
// UnlockedSlot.SaveWithDuress).
func (u *UnlockedSlot) openDuressContent() (duressIdx int, duressKi []byte, duress *Keystore, err error) {
	duressKi, err = OpenDuressAccess(u.Ki, u.Identity.DuressAccess)
	if err != nil {
		return 0, nil, nil, err
	}
	duressIdx, ok := FindSlotByKi(u.Container, duressKi)
	if !ok {
		return 0, nil, nil, errors.New(i18n.T("keystore.err_duress_slot_not_found"))
	}
	plain, err := openSlotContent(u.Container.Slots[duressIdx], duressKi)
	if err != nil {
		return 0, nil, nil, err
	}
	var out Keystore
	if err := json.Unmarshal(plain, &out); err != nil {
		return 0, nil, nil, errors.New(i18n.T("keystore.err_parse_json", err))
	}
	out.mu = &sync.Mutex{}
	return duressIdx, duressKi, &out, nil
}

// fillMirroredPlaceholder consumes one pending placeholder on u's own
// identity and one on duress, writes real into the former, and
// fakeContact(existingFirstNames) into the latter — existingFirstNames
// holds every other non-empty duress contact's current Username, letting
// fakeContact detect a collision with its newly generated name and
// disambiguate accordingly. Each side's own growth pool decides
// independently whether this consume also needs to create a new batch
// of empty placeholders. Mutates both u.Identity and duress in memory.
func (u *UnlockedSlot) fillMirroredPlaceholder(duress *Keystore, real Contact, fakeContact func(existingFirstNames map[string]bool) Contact) (realIdx int, err error) {
	realIdx, newRealLen, ok := u.Identity.ContactPendingIdx.consume(len(u.Identity.Contacts))
	if !ok {
		return 0, errors.New(i18n.T("keystore.err_no_empty_contact_slot"))
	}
	dIdx, newDuressLen, ok := duress.ContactPendingIdx.consume(len(duress.Contacts))
	if !ok {
		return 0, errors.New(i18n.T("keystore.err_no_empty_contact_slot"))
	}

	for len(u.Identity.Contacts) < newRealLen {
		u.Identity.Contacts = append(u.Identity.Contacts, Contact{})
	}
	u.Identity.Contacts[realIdx] = real
	if u.Identity.ContactMirrorDuressIdx == nil {
		u.Identity.ContactMirrorDuressIdx = map[int]int{}
	}
	u.Identity.ContactMirrorDuressIdx[realIdx] = dIdx

	for len(duress.Contacts) < newDuressLen {
		duress.Contacts = append(duress.Contacts, Contact{})
	}
	existingFirstNames := map[string]bool{}
	for i, c := range duress.Contacts {
		if i != dIdx && c.Username != "" {
			existingFirstNames[c.Username] = true
		}
	}
	duress.Contacts[dIdx] = fakeContact(existingFirstNames)
	return realIdx, nil
}

// AddMirroredContacts is the single insertion tool for a mirrored
// contact, covering both the one-at-a-time case (a direct /cnt-add, one
// element in incoming) and a batch merge (sync/backup import, several
// elements at once): for each element, an already-known IdentityPub
// only updates LocalName/MLKEMPub in place (never touches duress — the
// device-identity relationship fields are intentionally cleared,
// renegotiated locally), while a genuinely new one goes through
// fillMirroredPlaceholder. fromDevicePub attributes sibling-revocation
// data the same way regardless of which branch an entry took.
//
// Any incoming entry whose IdentityPub already has a tombstone row
// (u.Identity.HasDeletedContact) is skipped entirely — neither inserted
// nor merged into an update — and its IdentityPub collected into
// rejected, so the caller can reply to fromDevicePub with that
// tombstone row (see Keystore.DeletedContactRow).
//
// Mutates u.Identity in memory; returns what the caller must then pass
// to u.SaveWithDuress to persist both sides together (skip the save
// entirely if added==0 and updated==0).
func (u *UnlockedSlot) AddMirroredContacts(incoming []Contact, fromDevicePub []byte, fakeContact func(existingFirstNames map[string]bool) Contact) (added, updated int, rejected [][]byte, duressIdx int, duressKi, duressPlain []byte, err error) {
	duressIdx, duressKi, duress, err := u.openDuressContent()
	if err != nil {
		return 0, 0, nil, 0, nil, nil, err
	}

	for _, inc := range incoming {
		if u.Identity.HasDeletedContact(inc.IdentityPub) {
			rejected = append(rejected, inc.IdentityPub)
			continue
		}
		incDevices := inc.Devices
		incSiblingRevocations := inc.SiblingRevocations
		idx := -1
		for i, ex := range u.Identity.Contacts {
			if len(ex.IdentityPub) == 0 {
				continue // empty placeholder, never a real existing contact
			}
			if string(ex.IdentityPub) == string(inc.IdentityPub) {
				idx = i
				changed := false
				if inc.LocalName != "" && inc.LocalName != ex.LocalName {
					u.Identity.Contacts[i].LocalName = inc.LocalName
					changed = true
				}
				if len(inc.MLKEMPub) > 0 && string(inc.MLKEMPub) != string(ex.MLKEMPub) {
					u.Identity.Contacts[i].MLKEMPub = inc.MLKEMPub
					changed = true
				}
				if changed {
					updated++
				}
				break
			}
		}
		if idx == -1 {
			inc.Devices = nil
			inc.SiblingRevocations = nil
			inc.Verified = false
			inc.KnownDevicePub = nil
			realIdx, err := u.fillMirroredPlaceholder(duress, inc, fakeContact)
			if err != nil {
				return added, updated, rejected, 0, nil, nil, err
			}
			idx = realIdx
			added++
		}
		u.Identity.mergeSiblingRevocationsLocked(idx, fromDevicePub, incDevices, incSiblingRevocations)
	}

	duressPlain, err = json.Marshal(duress)
	if err != nil {
		return added, updated, rejected, 0, nil, nil, errors.New(i18n.T("keystore.err_marshal", err))
	}
	return added, updated, rejected, duressIdx, duressKi, duressPlain, nil
}

// fillPlaceholder is fillMirroredPlaceholder's counterpart for a
// session with no duress mirror to keep in sync — consumes one pending
// placeholder on u's own identity only. Mutates u.Identity in memory.
func (u *UnlockedSlot) fillPlaceholder(real Contact) (realIdx int, err error) {
	realIdx, newRealLen, ok := u.Identity.ContactPendingIdx.consume(len(u.Identity.Contacts))
	if !ok {
		return 0, errors.New(i18n.T("keystore.err_no_empty_contact_slot"))
	}
	for len(u.Identity.Contacts) < newRealLen {
		u.Identity.Contacts = append(u.Identity.Contacts, Contact{})
	}
	u.Identity.Contacts[realIdx] = real
	return realIdx, nil
}

// AddPlainContacts is AddMirroredContacts' counterpart for a session
// that has no duress mirror to keep in sync — the duress identity
// itself, managing its own contacts directly, since no further duress
// exists beneath it to mirror into (duress's own DuressAccess field is
// random noise, never a real wrapped key — see RandomDuressAccessField
// and openDuressContent's doc comment). Mutates u.Identity in memory;
// the caller persists with u.SaveSlot (never SaveWithDuress).
func (u *UnlockedSlot) AddPlainContacts(incoming []Contact, fromDevicePub []byte) (added, updated int, rejected [][]byte, err error) {
	for _, inc := range incoming {
		if u.Identity.HasDeletedContact(inc.IdentityPub) {
			rejected = append(rejected, inc.IdentityPub)
			continue
		}
		incDevices := inc.Devices
		incSiblingRevocations := inc.SiblingRevocations
		idx := -1
		for i, ex := range u.Identity.Contacts {
			if len(ex.IdentityPub) == 0 {
				continue // empty placeholder, never a real existing contact
			}
			if string(ex.IdentityPub) == string(inc.IdentityPub) {
				idx = i
				changed := false
				if inc.LocalName != "" && inc.LocalName != ex.LocalName {
					u.Identity.Contacts[i].LocalName = inc.LocalName
					changed = true
				}
				if len(inc.MLKEMPub) > 0 && string(inc.MLKEMPub) != string(ex.MLKEMPub) {
					u.Identity.Contacts[i].MLKEMPub = inc.MLKEMPub
					changed = true
				}
				if changed {
					updated++
				}
				break
			}
		}
		if idx == -1 {
			inc.Devices = nil
			inc.SiblingRevocations = nil
			inc.Verified = false
			inc.KnownDevicePub = nil
			realIdx, err := u.fillPlaceholder(inc)
			if err != nil {
				return added, updated, rejected, err
			}
			idx = realIdx
			added++
		}
		u.Identity.mergeSiblingRevocationsLocked(idx, fromDevicePub, incDevices, incSiblingRevocations)
	}
	return added, updated, rejected, nil
}

// EmptyPlainContact is EmptyMirroredContact's counterpart for a session
// that has no duress mirror to keep in sync (see AddPlainContacts).
func (u *UnlockedSlot) EmptyPlainContact(realContactIdx int) error {
	if realContactIdx < 0 || realContactIdx >= len(u.Identity.Contacts) {
		return errors.New(i18n.T("keystore.err_contact_not_found"))
	}
	u.Identity.Contacts[realContactIdx] = Contact{}
	u.Identity.ContactPendingIdx.Pending = append(u.Identity.ContactPendingIdx.Pending, realContactIdx)
	delete(u.Identity.ContactMirrorDuressIdx, realContactIdx)
	return nil
}

// EmptyMirroredContact is the single deletion tool for a mirrored
// contact: empties realContactIdx's values in place on u's own identity
// (never removes the slot) — its index goes back into
// ContactPendingIdx.Pending, available for a future fill. The
// corresponding duress contact, if the real one was ever actually
// filled, is emptied and recycled the same way on duress's own side —
// a contact that was never filled via AddMirroredContacts has no mirror
// to empty at all (hadMirror is false, nothing on the duress side is
// touched). The now-stale real→duress mapping is dropped.
func (u *UnlockedSlot) EmptyMirroredContact(realContactIdx int) (duressIdx int, duressKi, duressPlain []byte, hadMirror bool, err error) {
	if realContactIdx < 0 || realContactIdx >= len(u.Identity.Contacts) {
		return 0, nil, nil, false, errors.New(i18n.T("keystore.err_contact_not_found"))
	}
	u.Identity.Contacts[realContactIdx] = Contact{}
	u.Identity.ContactPendingIdx.Pending = append(u.Identity.ContactPendingIdx.Pending, realContactIdx)

	dIdx, found := u.Identity.ContactMirrorDuressIdx[realContactIdx]
	if !found {
		return 0, nil, nil, false, nil
	}
	delete(u.Identity.ContactMirrorDuressIdx, realContactIdx)

	duressIdx, duressKi, duress, err := u.openDuressContent()
	if err != nil {
		return 0, nil, nil, false, err
	}
	if dIdx < 0 || dIdx >= len(duress.Contacts) {
		return 0, nil, nil, false, errors.New(i18n.T("keystore.err_contact_not_found"))
	}
	duress.Contacts[dIdx] = Contact{}
	duress.ContactPendingIdx.Pending = append(duress.ContactPendingIdx.Pending, dIdx)

	duressPlain, err = json.Marshal(duress)
	if err != nil {
		return 0, nil, nil, false, errors.New(i18n.T("keystore.err_marshal", err))
	}
	return duressIdx, duressKi, duressPlain, true, nil
}
