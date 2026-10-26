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

import "time"

// TimeLayout is the layout used everywhere the app prints hours/minutes,
// identical to the format Tor itself uses to timestamp each log line (e.g.
// "Jul 27 19:17:17.558"). "_2" is the space-padded (not zero-padded) day of
// the month, same as Tor's log.
const TimeLayout = "Jan _2 15:04:05.000"

// Now formats the current instant with TimeLayout.
func Now() string {
	return time.Now().Format(TimeLayout)
}
