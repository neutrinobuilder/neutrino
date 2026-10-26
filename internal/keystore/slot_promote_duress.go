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

// PromoteDuress returns a new UnlockedSlot for the shared duress
// identity, reachable directly from u (K_i_duress wrapped under u's
// own K_i, DuressAccess/OpenDuressAccess, no password needed). A nuke
// trigger (cmdNukeX, executeRemoteNuke, duress at the lock screen) uses
// this to keep the running process alive AS duress instead of
// terminating or returning to the login screen. Duress elevated this
// way never regenerates a protection scheme of its own, by design: it
// is the same shared duress every real identity in the file already
// reaches.
//
// PasswordIdentity is left empty on the returned UnlockedSlot, u only
// knows the REAL identity's own password, never duress's; a later
// operation that needs it (RewrapOwnSlot, AddRealIdentity) simply isn't
// available on a promoted session.
func (u *UnlockedSlot) PromoteDuress() (*UnlockedSlot, error) {
	duressIdx, duressKi, duress, err := u.openDuressContent()
	if err != nil {
		return nil, err
	}
	return &UnlockedSlot{
		Container:    u.Container,
		Idx:          duressIdx,
		Ki:           duressKi,
		Identity:     duress,
		PasswordFile: u.PasswordFile,
	}, nil
}
