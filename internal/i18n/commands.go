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

package i18n

// CmdID is a canonical command identifier. The calling package (e.g.
// internal/client) defines its own constants of this type and registers
// their names with RegisterCommands; from then on CommandName/
// ResolveCommand resolve them. Command names are always in English,
// regardless of the interface's active language (set with SetActive).
type CmdID int

var (
	cmdNames   map[CmdID]string
	cmdReverse map[string]CmdID
)

// RegisterCommands installs the command→name table. names[id] is the
// surface string the parser recognizes (e.g. "/invite") for that CmdID.
func RegisterCommands(names map[CmdID]string) {
	cmdNames = names
	cmdReverse = make(map[string]CmdID, len(names))
	for id, name := range names {
		cmdReverse[name] = id
	}
}

// CommandName returns the command's string (with slash).
func CommandName(id CmdID) string {
	return cmdNames[id]
}

// ResolveCommand resolves a word typed by the user (e.g. "/invite") into
// its canonical CmdID.
func ResolveCommand(word string) (CmdID, bool) {
	id, ok := cmdReverse[word]
	return id, ok
}
