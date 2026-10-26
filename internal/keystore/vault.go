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

	"github.com/awnumar/memguard"
)

// vaultBytes protects a low-frequency-use secret (the keys retained
// during a rotation transition: OldIdentityKey/OldMLKEMKey/OldMLDSAKey)
// by keeping it encrypted in RAM (memguard.Enclave, XSalsa20Poly1305)
// instead of as a plaintext []byte for the whole rotation window. It
// doesn't protect against an attacker with active/continuous RAM access
// (a structural limit, not one of this implementation): it only reduces
// the at-rest surface (swap, core dump, partial leak), moving "the thing
// that must never leak" onto a single small block managed by memguard
// instead of the whole key.
//
// The three fields are EXPORTED (IdentityKey/OldIdentityKey/... in
// the Keystore struct) because encoding/json ignores unexported fields
// their TYPE, vaultBytes, is unexported: an external package can
// still read/write the field, but can't construct a vaultBytes with
// arbitrary content (no literal accessible outside this package), nor
// read its raw bytes without going through bytes()/open().
type vaultBytes struct {
	enc *memguard.Enclave
}

// newVaultBytes moves b into an encrypted Enclave. memguard.NewBufferFromBytes
// zeroes b itself after copying it, an intended side effect: moving an
// existing field into a vaultBytes (e.g. startKeyRotationLocked, which
// does `ks.OldIdentityKey = ks.IdentityKey` before replacing IdentityKey
// with the new key) gets the old backing array zeroed without writing
// dedicated code for it.
func newVaultBytes(b []byte) vaultBytes {
	if len(b) == 0 {
		return vaultBytes{}
	}
	return vaultBytes{enc: memguard.NewBufferFromBytes(b).Seal()}
}

// isSet reports whether the vault holds a secret.
func (v vaultBytes) isSet() bool { return v.enc != nil }

// open decrypts the secret into a LockedBuffer, passes the plaintext to
// fn, then destroys (zeroes) the buffer as soon as fn returns, even on
// a panic in fn, thanks to the defer. Use to build a key object that no
// longer holds a reference to the source buffer once returned
// (mldsa65.NewKeyFromSeed/mlkem.NewDecapsulationKey768 expand the seed
// internally, not aliasing what was passed in). fn receives nil if the
// vault is empty or decryption fails.
func (v vaultBytes) open(fn func(plain []byte)) {
	if v.enc == nil {
		fn(nil)
		return
	}
	lb, err := v.enc.Open()
	if err != nil {
		fn(nil)
		return
	}
	defer lb.Destroy()
	fn(lb.Bytes())
}

// bytes returns a plaintext COPY owned by the caller, use only where
// the value must survive beyond the single call (e.g. AbortKeyRotation,
// which must put the old key back into a normal
// IdentityKey/MLKEMKey/MLDSAKey field, outside the vault). The caller
// inherits the responsibility of not holding it longer than needed, no
// zeroing guarantee beyond this point (a known Go limitation, no
// equivalent of Rust's zeroize).
func (v vaultBytes) bytes() []byte {
	var out []byte
	v.open(func(plain []byte) {
		if plain == nil {
			return
		}
		out = make([]byte, len(plain))
		copy(out, plain)
	})
	return out
}

// MarshalJSON/UnmarshalJSON make vaultBytes transparent on the wire: on
// disk (or in an exported backup/sync) it is a plain base64 []byte,
// decrypted only for the duration of the marshal/unmarshal.
//
// Note: omitempty on a struct-typed field never makes standard
// encoding/json omit the field (a library limitation, not of this code)
// an empty vaultBytes serializes as `null` instead of being entirely
// absent. No functional impact: the round-trip remains identical.
func (v vaultBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.bytes())
}

func (v *vaultBytes) UnmarshalJSON(data []byte) error {
	var raw []byte
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = newVaultBytes(raw)
	return nil
}
