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

// gcmTagLen is the standard AES-GCM authentication tag size — used only
// to size the noise filler below the same as a real sealed blob, never
// to implement GCM itself (that stays in aesgcmEncrypt/aesgcmDecrypt).
const gcmTagLen = 16

// DuressAccessField is the fixed-size field every identity (real or
// duress, same schema) carries, written once at its creation:
//   - in a real identity, it is K_i_duress sealed directly under the
//     identity's own K_i (no password, no KDF — whoever already
//     unlocked that real identity already holds its K_i, so this field
//     yields K_i_duress directly: no
//     re-authentication needed when a trigger fires mid-session).
//   - in the duress identity itself, it is random noise of the exact
//     same shape: duress has no further duress to reach, and leaving
//     this field structurally absent would itself be a distinguishing
//     mark.
type DuressAccessField struct {
	Nonce   []byte `json:"nonce"`   // nonceLen bytes
	Wrapped []byte `json:"wrapped"` // keyLen+gcmTagLen bytes
}

// SealDuressAccess wraps duressKi directly under ownKi — used when
// creating or promoting a real identity, by whoever already has
// legitimate access to both keys at that moment.
func SealDuressAccess(ownKi, duressKi []byte) (DuressAccessField, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return DuressAccessField{}, errors.New(i18n.T("keystore.err_nonce", err))
	}
	wrapped, err := aesgcmEncrypt(ownKi, nonce, duressKi)
	if err != nil {
		return DuressAccessField{}, err
	}
	return DuressAccessField{Nonce: nonce, Wrapped: wrapped}, nil
}

// OpenDuressAccess recovers K_i_duress from a real identity's own
// DuressAccessField, using the K_i that identity's own login already
// produced — no password, no derivation, ready in RAM for the whole
// session.
func OpenDuressAccess(ownKi []byte, f DuressAccessField) ([]byte, error) {
	plain, err := aesgcmDecrypt(ownKi, f.Nonce, f.Wrapped)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_wrong_password"))
	}
	return plain, nil
}

// RandomDuressAccessField fills a field of the identical shape with
// random bytes — used for the duress identity's own copy, which must
// never contain a real wrapped key (see DuressAccessField's doc
// comment).
func RandomDuressAccessField() (DuressAccessField, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return DuressAccessField{}, errors.New(i18n.T("keystore.err_nonce", err))
	}
	wrapped := make([]byte, keyLen+gcmTagLen)
	if _, err := rand.Read(wrapped); err != nil {
		return DuressAccessField{}, errors.New(i18n.T("keystore.err_slot_random", err))
	}
	return DuressAccessField{Nonce: nonce, Wrapped: wrapped}, nil
}
