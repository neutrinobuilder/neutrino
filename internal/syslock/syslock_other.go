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

//go:build !linux || android

package syslock

import "context"

// Watch is unavailable outside "desktop" Linux — no systemd-logind D-Bus
// there. Android's own screen-off signal (ACTION_SCREEN_OFF, JNI bridge)
// is not handled by this package. Returns nil, same "feature unavailable" contract as
// the Linux implementation when logind/D-Bus can't be reached.
func Watch(ctx context.Context) <-chan struct{} {
	return nil
}
