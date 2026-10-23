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

import "testing"

func TestRegisterCommandsRoundtrip(t *testing.T) {
	RegisterCommands(map[CmdID]string{
		1: "/foo",
		2: "/bar",
	})

	if got := CommandName(1); got != "/foo" {
		t.Errorf("CommandName(1) = %q, want /foo", got)
	}
	if got := CommandName(2); got != "/bar" {
		t.Errorf("CommandName(2) = %q, want /bar", got)
	}

	if id, ok := ResolveCommand("/foo"); !ok || id != 1 {
		t.Errorf("ResolveCommand(/foo) = (%v, %v), want (1, true)", id, ok)
	}
	if id, ok := ResolveCommand("/bar"); !ok || id != 2 {
		t.Errorf("ResolveCommand(/bar) = (%v, %v), want (2, true)", id, ok)
	}
}

func TestResolveCommandUnknown(t *testing.T) {
	RegisterCommands(map[CmdID]string{1: "/foo"})
	if _, ok := ResolveCommand("/does-not-exist"); ok {
		t.Error("ResolveCommand: unknown command resolved unexpectedly")
	}
}

func TestRegisterCommandsOverwritesPrevious(t *testing.T) {
	RegisterCommands(map[CmdID]string{1: "/old"})
	if _, ok := ResolveCommand("/old"); !ok {
		t.Fatal("setup: /old not resolved before the overwrite")
	}

	RegisterCommands(map[CmdID]string{1: "/new"})
	if _, ok := ResolveCommand("/old"); ok {
		t.Error("RegisterCommands: the old name still resolves after the overwrite")
	}
	if got := CommandName(1); got != "/new" {
		t.Errorf("CommandName(1) = %q, want /new after the overwrite", got)
	}
}
