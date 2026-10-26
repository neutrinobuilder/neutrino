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

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"neutrino/internal/client"
	"neutrino/internal/i18n"
)

// TestHandleInputClearAllEntersConfirmMode verifies "/sec-clear-all" only
// arms the confirmation popup — it must never wipe anything by itself.
func TestHandleInputClearAllEntersConfirmMode(t *testing.T) {
	m := &model{}
	cmd := m.handleInput("/sec-clear-all")
	if !m.clearAllConfirmMode {
		t.Fatal("expected clearAllConfirmMode to be true")
	}
	if m.clearAllOnExit {
		t.Fatal("expected clearAllOnExit to still be false before confirmation")
	}
	if cmd != nil {
		t.Fatal("expected a nil cmd while only arming the confirmation")
	}
}

// TestClearAllConfirmNoCancels verifies the "no" answer cancels without
// setting clearAllOnExit.
func TestClearAllConfirmNoCancels(t *testing.T) {
	m := model{clearAllConfirmMode: true}
	no := []rune(i18n.T("common.no"))[0]
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{no}})
	fm := newModel.(model)
	if fm.clearAllConfirmMode {
		t.Fatal("expected clearAllConfirmMode to be cleared")
	}
	if fm.clearAllOnExit {
		t.Fatal("expected clearAllOnExit to remain false")
	}
	if cmd != nil {
		t.Fatal("expected a nil cmd on cancel")
	}
}

// TestClearAllConfirmYesQuits verifies the "yes" answer sets
// clearAllOnExit and returns tea.Quit — the actual wipe runs only after
// the TUI exits (cmd/main.go:wipeConfigDir), never from inside this Cmd.
func TestClearAllConfirmYesQuits(t *testing.T) {
	m := model{clearAllConfirmMode: true}
	yes := []rune(i18n.T("common.yes"))[0]
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{yes}})
	fm := newModel.(model)
	if fm.clearAllConfirmMode {
		t.Fatal("expected clearAllConfirmMode to be cleared")
	}
	if !fm.clearAllOnExit {
		t.Fatal("expected clearAllOnExit to be true")
	}
	if cmd == nil {
		t.Fatal("expected a non-nil tea.Quit cmd")
	}
	if msg := cmd(); msg != tea.Quit() {
		t.Fatalf("expected tea.Quit message, got %#v", msg)
	}
}

// TestClearAllConfirmEscCancels verifies Esc cancels just like "no".
func TestClearAllConfirmEscCancels(t *testing.T) {
	m := model{clearAllConfirmMode: true}
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	fm := newModel.(model)
	if fm.clearAllConfirmMode {
		t.Fatal("expected clearAllConfirmMode to be cleared")
	}
	if cmd != nil {
		t.Fatal("expected a nil cmd on Esc")
	}
}

// TestCommandListIncludesClearAll verifies /sec-clear-all is registered
// in the palette/help table like any other command.
func TestCommandListIncludesClearAll(t *testing.T) {
	for _, item := range client.CommandList() {
		if item.Cmd == "/sec-clear-all" {
			return
		}
	}
	t.Fatal("/sec-clear-all not found in client.CommandList()")
}
