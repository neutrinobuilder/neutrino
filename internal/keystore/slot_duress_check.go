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

// CandidateIsDuressPassword reports whether candidate (combined with
// u's own, already-known password_file) is the shared duress
// identity's own password_identity — checked via K_i_duress
// (u.Identity.DuressAccess), without needing duress's own password
// known separately.
func (u *UnlockedSlot) CandidateIsDuressPassword(candidate string) bool {
	duressKi, err := OpenDuressAccess(u.Ki, u.Identity.DuressAccess)
	if err != nil {
		return false
	}
	duressIdx, ok := FindSlotByKi(u.Container, duressKi)
	if !ok {
		return false
	}
	got, ok := unwrapKi(u.Container.Slots[duressIdx], u.PasswordFile, candidate)
	return ok && string(got) == string(duressKi)
}
