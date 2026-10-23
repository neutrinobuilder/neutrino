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
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"os"

	"golang.org/x/crypto/argon2"

	"neutrino/internal/i18n"
)

// fileMagic marks the plaintext header carrying the automatic NUKE
// password (duress) verifier. A file without it starts directly with
// salt||nonce||ciphertext: its first 4 bytes are random salt, and the
// probability of them coincidentally matching these 4 fixed bytes is
// negligible.
var fileMagic = [4]byte{'N', 'T', 'R', 'K'}

const (
	fileFormatVersion = 1
	duressSaltLen      = 16
	duressHashLen      = 32
)

// DuressConfig is the plaintext verifier for the automatic NUKE
// password — Salt+Hash (Argon2id, same parameters as the regular
// password), written OUTSIDE the keystore's encrypted payload on
// purpose: it must be checkable before/without decrypting anything, to
// distinguish "wrong password" from "NUKE password" without ever
// revealing which of the two was typed (see CheckDuress) — an Argon2id
// verifier is one-way, it doesn't allow recovering the password from a
// stolen file.
type DuressConfig struct {
	Salt []byte
	Hash []byte
}

// NewDuressConfig derives the verifier for a new automatic NUKE
// password. Must then be passed to (*Keystore).SetDuress and persisted
// with Save.
func NewDuressConfig(password string) (*DuressConfig, error) {
	salt := make([]byte, duressSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New(i18n.T("keystore.err_salt", err))
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, duressHashLen)
	return &DuressConfig{Salt: salt, Hash: hash}, nil
}

// Matches compares password (constant time) against the verifier.
func (d *DuressConfig) Matches(password string) bool {
	if d == nil {
		return false
	}
	got := argon2.IDKey([]byte(password), d.Salt, argonTime, argonMemory, argonThreads, duressHashLen)
	return subtle.ConstantTimeCompare(got, d.Hash) == 1
}

// SetDuress sets (or replaces) the automatic NUKE password for the
// whole file — shared by every linked identity (see the siblings
// field), never per-identity: a keystore file has a single duress
// verifier. password must not coincide with the keystore's real one
// (the caller guarantees this: there's no way to know it here, the two
// passwords never transit together at the same point in the code).
func (ks *Keystore) SetDuress(password string) error {
	cfg, err := NewDuressConfig(password)
	if err != nil {
		return err
	}
	ks.duress = cfg
	for _, s := range ks.siblings {
		s.duress = cfg
	}
	return nil
}

// ClearDuress removes the automatic NUKE password (if set).
func (ks *Keystore) ClearDuress() {
	ks.duress = nil
	for _, s := range ks.siblings {
		s.duress = nil
	}
}

// HasDuress reports whether an automatic NUKE password is set.
func (ks *Keystore) HasDuress() bool {
	return ks.duress != nil
}

// CheckDuress reads ONLY the file's plaintext header (never the
// encrypted payload, never the real password) and reports whether
// password matches the automatic NUKE password, if one is configured —
// usable even when password is NOT the keystore's real one: that's
// exactly the point, distinguishing the two without decrypting anything.
// False if the file doesn't exist, has no header, or has no NUKE
// password configured.
func CheckDuress(path, password string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	cfg, _, ok := readDuressHeader(data)
	if !ok || cfg == nil {
		return false
	}
	return cfg.Matches(password)
}

// readDuressHeader recognizes the plaintext header (if present) at the
// start of data: returns the DuressConfig if present and the rest of the
// file (salt||nonce||ciphertext). ok is false if data has no header — in
// that case rest == data, unchanged, and decryptFile reads it directly.
func readDuressHeader(data []byte) (cfg *DuressConfig, rest []byte, ok bool) {
	if len(data) < len(fileMagic)+2 || !bytes.Equal(data[:len(fileMagic)], fileMagic[:]) {
		return nil, data, false
	}
	offset := len(fileMagic) + 1 // magic + formatVersion (reserved, not yet used)
	hasDuress := data[offset] == 1
	offset++
	if hasDuress {
		if len(data) < offset+duressSaltLen+duressHashLen {
			return nil, data, false
		}
		cfg = &DuressConfig{
			Salt: append([]byte(nil), data[offset:offset+duressSaltLen]...),
			Hash: append([]byte(nil), data[offset+duressSaltLen:offset+duressSaltLen+duressHashLen]...),
		}
		offset += duressSaltLen + duressHashLen
	}
	return cfg, data[offset:], true
}

// writeDuressHeader serializes the plaintext header to prepend to
// salt||nonce||ciphertext in Save — cfg nil is a valid header (no NUKE
// password configured), not the absence of a header: Save always writes
// it, so a NUKE password set later requires no format change.
func writeDuressHeader(cfg *DuressConfig) []byte {
	header := append([]byte{}, fileMagic[:]...)
	header = append(header, fileFormatVersion)
	if cfg != nil {
		header = append(header, 1)
		header = append(header, cfg.Salt...)
		header = append(header, cfg.Hash...)
	} else {
		header = append(header, 0)
	}
	return header
}
