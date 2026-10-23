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

// Package e2e holds end-to-end scenarios: several real neutrino
// processes, started in agent mode on the loopback transport, driven
// through the agent socket exactly as a person would drive the TUI.
//
// The scenarios are built only with the neutrino_agent tag:
//
//	go test -tags=neutrino_agent ./internal/e2e/
//
// Without the tag this package is empty and plain `go test ./...` skips it.
package e2e
