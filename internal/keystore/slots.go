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
	"encoding/json"
	"errors"

	"neutrino/internal/i18n"
)

// slotEntry is one independent "mini-keystore" inside the N-slot
// keystore container — a real identity, the shared duress identity, or
// an unassigned noise slot all have this exact same shape, so none is
// structurally distinguishable from the others without the right
// password combination.
type slotEntry struct {
	Salt         []byte // saltLen bytes, Argon2id salt for this slot's wrap key
	WrapNonce    []byte // nonceLen bytes, AES-GCM nonce for the wrapped K_i
	WrappedKi    []byte // AES-256-GCM(wrapKey, K_i) — fixed size regardless of slot type
	ContentNonce []byte // nonceLen bytes, AES-GCM nonce for the slot's own content
	Content      []byte // AES-256-GCM(K_i, slot payload) — grows only, never shrinks
}

// deriveSlotWrapKey derives a slot's wrap key from the two concatenated
// passwords, never separately verifiable: a single yes/no on the whole
// combination, so an attacker who finds one password gains nothing
// checkable about the other (multiplicative, not additive, brute-force
// cost).
func deriveSlotWrapKey(passwordFile, passwordIdentity string, salt []byte) []byte {
	return deriveKey([]byte(passwordFile+"\x00"+passwordIdentity), salt)
}

// newSlotKi generates a new, independent random content key for a slot:
// AES-256-GCM encrypts that slot's own content directly under it, no
// Argon2id on the content itself — only the wrap step is slow.
func newSlotKi() ([]byte, error) {
	ki := make([]byte, keyLen)
	if _, err := rand.Read(ki); err != nil {
		return nil, errors.New(i18n.T("keystore.err_slot_random", err))
	}
	return ki, nil
}

// newSlot wraps ki under the given password combination into a freshly
// salted slot. The returned slot has no content yet — the caller must
// seal it with sealSlotContent before it is fit to write to disk (a slot
// is never left without content, see sealSlotContent).
func newSlot(ki []byte, passwordFile, passwordIdentity string) (slotEntry, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return slotEntry{}, errors.New(i18n.T("keystore.err_salt", err))
	}
	wrapNonce := make([]byte, nonceLen)
	if _, err := rand.Read(wrapNonce); err != nil {
		return slotEntry{}, errors.New(i18n.T("keystore.err_nonce", err))
	}
	wrappedKi, err := aesgcmEncrypt(deriveSlotWrapKey(passwordFile, passwordIdentity, salt), wrapNonce, ki)
	if err != nil {
		return slotEntry{}, err
	}
	return slotEntry{Salt: salt, WrapNonce: wrapNonce, WrappedKi: wrappedKi}, nil
}

// newNoiseSlot creates a slot wrapped under random bytes instead of any
// typed password — nobody will ever open it on purpose, but its shape
// on disk (salt/wrapNonce/wrappedKi/contentNonce/content) is identical
// to a real slot's: indistinguishable from genuine material without an
// unwrap attempt. Its CONTENT must be non-trivial too, not just the
// wrap — a noise slot with an empty/short Content while real/duress
// slots carry a full JSON payload would be a size tell visible to
// anyone with the raw file, no password needed (AES-GCM ciphertext
// length reveals plaintext length).
//
// This slot's only job is padding the file's slot count/size — it never
// carries contacts/mirror state like duress does. The filler is a
// freshly-generated throwaway identity (New("")), same real keys and
// rough size as a newborn real identity, nothing more.
func newNoiseSlot() (slotEntry, error) {
	randomPassword := make([]byte, keyLen)
	if _, err := rand.Read(randomPassword); err != nil {
		return slotEntry{}, errors.New(i18n.T("keystore.err_slot_random", err))
	}
	ki, err := newSlotKi()
	if err != nil {
		return slotEntry{}, err
	}
	// passwordFile left empty on purpose: a noise slot's "password" is
	// opaque random bytes nobody will ever type, never meant to be
	// combined with the file's real password_file.
	slot, err := newSlot(ki, "", string(randomPassword))
	if err != nil {
		return slotEntry{}, err
	}

	filler, err := New("")
	if err != nil {
		return slotEntry{}, err
	}
	plain, err := json.Marshal(filler)
	if err != nil {
		return slotEntry{}, errors.New(i18n.T("keystore.err_marshal", err))
	}
	if err := sealSlotContent(&slot, ki, plain); err != nil {
		return slotEntry{}, err
	}
	return slot, nil
}

// unwrapKi attempts to recover a slot's raw content key K_i from a
// candidate password combination. ok is false if the combination
// doesn't match this slot — the same outcome whether the slot belongs to
// someone else, is a noise slot, or the password is simply wrong: no
// distinguishable error between the three.
func unwrapKi(s slotEntry, passwordFile, passwordIdentity string) (ki []byte, ok bool) {
	key := deriveSlotWrapKey(passwordFile, passwordIdentity, s.Salt)
	plain, err := aesgcmDecrypt(key, s.WrapNonce, s.WrappedKi)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// sealSlotContent encrypts plaintext directly under K_i (no Argon2id —
// only the wrap step above is slow) and stores it into s, replacing any
// previous content nonce. Callers never shrink plaintext across
// successive calls on the same slot.
func sealSlotContent(s *slotEntry, ki, plaintext []byte) error {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return errors.New(i18n.T("keystore.err_nonce", err))
	}
	ct, err := aesgcmEncrypt(ki, nonce, plaintext)
	if err != nil {
		return err
	}
	s.ContentNonce = nonce
	s.Content = ct
	return nil
}

// openSlotContent decrypts a slot's content under its already-recovered K_i.
func openSlotContent(s slotEntry, ki []byte) ([]byte, error) {
	plain, err := aesgcmDecrypt(ki, s.ContentNonce, s.Content)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_wrong_password"))
	}
	return plain, nil
}

// passwordIdentityCollides reports whether passwordIdentity (combined
// with passwordFile) already opens ANY existing slot in slots — must be
// checked before assigning a NEW password_identity to a real identity or
// to duress: the file's login tries one candidate combination against
// every slot, so two slots sharing the same combination would make
// login ambiguous (both would answer). Noise slots can never collide
// here: their wrap key is random, never derived from any typed
// password.
func passwordIdentityCollides(slots []slotEntry, passwordFile, passwordIdentity string) bool {
	for _, s := range slots {
		if _, ok := unwrapKi(s, passwordFile, passwordIdentity); ok {
			return true
		}
	}
	return false
}
