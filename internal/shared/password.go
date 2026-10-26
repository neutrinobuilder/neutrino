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

package shared

import (
	"crypto/rand"
	"math"
	"math/big"
	"strings"

	"github.com/tyler-smith/go-bip39"

	"neutrino/internal/i18n"
)

// GeneratePassphrase generates a random passphrase from n words of the
// BIP-39 wordlist (2048 words, ~11 bits of entropy each) — the same list
// already used for identity backup, so already vetted to be typeable
// unambiguously. Not an actual BIP-39 mnemonic (no checksum, no seed
// encoding): just n uniformly random words, meant for a long but
// memorable keystore password, Diceware-style.
func GeneratePassphrase(n int) (string, error) {
	wordList := bip39.GetWordList()
	max := big.NewInt(int64(len(wordList)))
	words := make([]string, n)
	for i := range words {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		words[i] = wordList[idx.Int64()]
	}
	return strings.Join(words, " "), nil
}

// PasswordStrengthLevel is a rough, dependency-free estimate of password
// strength — just length × observed alphabet size, not a real entropy
// calculation (doesn't detect dictionary words, known patterns, reuse).
// Serves as a general indication in the wizard and in /sec-passwd, not as the
// only defense: the real protection against offline brute-force is
// Argon2id.
type PasswordStrengthLevel int

const (
	PasswordVeryWeak PasswordStrengthLevel = iota
	PasswordWeak
	PasswordOK
	PasswordStrong
	PasswordVeryStrong
)

// PasswordStrength estimates pwd's bits of entropy (length in runes × log2
// of the alphabet size used: lowercase/uppercase/digits/spaces/symbols) and
// maps it to an approximate level.
func PasswordStrength(pwd string) PasswordStrengthLevel {
	if pwd == "" {
		return PasswordVeryWeak
	}
	var hasLower, hasUpper, hasDigit, hasSpace, hasSymbol bool
	length := 0
	for _, r := range pwd {
		length++
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == ' ':
			hasSpace = true
		default:
			hasSymbol = true
		}
	}
	alphabet := 0
	if hasLower {
		alphabet += 26
	}
	if hasUpper {
		alphabet += 26
	}
	if hasDigit {
		alphabet += 10
	}
	if hasSpace {
		alphabet++
	}
	if hasSymbol {
		alphabet += 32
	}
	if alphabet == 0 {
		alphabet = 1
	}
	bits := float64(length) * math.Log2(float64(alphabet))
	switch {
	case bits < 28:
		return PasswordVeryWeak
	case bits < 40:
		return PasswordWeak
	case bits < 60:
		return PasswordOK
	case bits < 80:
		return PasswordStrong
	default:
		return PasswordVeryStrong
	}
}

// Label returns the human-readable label of the level, in the active
// language.
func (l PasswordStrengthLevel) Label() string {
	switch l {
	case PasswordVeryWeak:
		return i18n.T("shared.password_very_weak")
	case PasswordWeak:
		return i18n.T("shared.password_weak")
	case PasswordOK:
		return i18n.T("shared.password_ok")
	case PasswordStrong:
		return i18n.T("shared.password_strong")
	default:
		return i18n.T("shared.password_very_strong")
	}
}
