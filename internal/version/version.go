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

// AppVersion is a manually incremented counter, not computed from build or
// commit metadata: the last digit increases by one on every completed unit
// of work, the middle digit increases by hand for a larger body of work
// (e.g. a full architectural redesign). Not a build number or a date — a
// plain progressive counter that lets the running instance be identified
// at a glance against a previous one. Shown by: the TUI (/info-app),
// `neutrino version`/`--version`, and the `neutrino --help` header.
const AppVersion = "0.0.49"

// Build is a finer-grained identifier than AppVersion — YYMMDDNNNN (two-digit
// year, month, day, a 4-digit sequence within that day), updated by hand
// alongside AppVersion, never computed automatically. Distinguishes which of
// several builds made on the same day is running.
const Build = "2610230007"

// Full returns AppVersion and Build combined — the single string shown
// everywhere the project displays its own version (TUI /info-app,
// `neutrino version`/`--version`/`--help`).
func Full() string {
	return AppVersion + " (build " + Build + ")"
}
