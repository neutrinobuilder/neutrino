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

// Package version exposes the application's version number — the single
// source of truth for the whole project.
package version

// AppVersion identifies a published release: it changes only when a new
// release is published, together with Build. Not computed from build or
// commit metadata. Shown by: the TUI (/info-app), `neutrino
// version`/`--version`, and the `neutrino --help` header.
const AppVersion = "0.0.49"

// Build is a finer-grained identifier than AppVersion — YYMMDDNNNN (two-digit
// year, month, day, a 4-digit sequence within that day), updated by hand
// alongside AppVersion, never computed automatically.
const Build = "2610230007"

// Dev is the development counter of builds made between two releases, set
// only by maintainer builds (build tag neutrino_personal). Empty in release
// builds, which therefore show only AppVersion and Build.
var Dev string

// Full returns AppVersion and Build combined, followed by " Dev.<n>" when Dev
// is set — the single string shown everywhere the project displays its own
// version (TUI /info-app, `neutrino version`/`--version`/`--help`).
func Full() string {
	s := AppVersion + " (build " + Build + ")"
	if Dev != "" {
		s += " Dev." + Dev
	}
	return s
}
