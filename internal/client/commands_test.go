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

package client

import (
	"testing"

	"neutrino/internal/i18n"
)

// TestCommandDefsUnique catches a duplicate name or a CmdID reused by mistake,
// something that would otherwise only surface at runtime (a command
// silently "hiding" another).
func TestCommandDefsUnique(t *testing.T) {
	seenNames := make(map[string]CmdID)
	seenIDs := make(map[CmdID]string)
	for _, d := range commandDefs {
		if other, ok := seenNames[d.name]; ok {
			t.Errorf("duplicate command name %q: used by both CmdID %d and %d", d.name, other, d.id)
		}
		seenNames[d.name] = d.id

		if other, ok := seenIDs[d.id]; ok {
			t.Errorf("duplicate CmdID %d: used by both %q and %q", d.id, other, d.name)
		}
		seenIDs[d.id] = d.name

		if d.name == "" || d.name[0] != '/' {
			t.Errorf("command %v has an invalid name %q (must start with /)", d.id, d.name)
		}
	}
}

// TestResolveCommandRoundtrip verifies that every command registered in
// commandDefs is resolvable via i18n.ResolveCommand and that
// i18n.CommandName returns the same name, the roundtrip actually used
// by the TUI's parser (splitCmd → ResolveCommand).
func TestResolveCommandRoundtrip(t *testing.T) {
	for _, d := range commandDefs {
		id, ok := i18n.ResolveCommand(d.name)
		if !ok {
			t.Errorf("ResolveCommand(%q) not resolved", d.name)
			continue
		}
		if id != d.id {
			t.Errorf("ResolveCommand(%q) = %v, want %v", d.name, id, d.id)
		}
		if got := i18n.CommandName(d.id); got != d.name {
			t.Errorf("CommandName(%v) = %q, want %q", d.id, got, d.name)
		}
	}
}

func TestResolveCommandUnknown(t *testing.T) {
	if _, ok := i18n.ResolveCommand("/does-not-exist"); ok {
		t.Error("want ResolveCommand to fail for an unknown command")
	}
}
