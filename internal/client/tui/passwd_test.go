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
)

// typeAndEnter feeds text then Enter through Update, as a person would at
// a masked prompt, returning the model and the last command.
func typeAndEnter(t *testing.T, m model, text string) (model, tea.Cmd) {
	t.Helper()
	if text != "" {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)})
		m = next.(model)
	}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return next.(model), cmd
}

// TestPasswordChangeUpdatesSessionPassword verifies that after a
// successful /sec-passwd the new password, not the old one, is the one
// /sec-backup checks for the rest of the session.
func TestPasswordChangeUpdatesSessionPassword(t *testing.T) {
	m := model{
		keystorePassword:  "old",
		changePassword:    func(oldPwd, newPwd string) error { return nil },
		getBackupMnemonic: func() ([]string, error) { return make([]string, 24), nil },
		tabs:              []*roomTab{{isConsole: true}},
	}
	m.pwdMode = 1
	m, _ = typeAndEnter(t, m, "old")
	m, _ = typeAndEnter(t, m, "new")
	m, cmd := typeAndEnter(t, m, "new")
	if cmd == nil {
		t.Fatal("expected the password change command")
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	if m.keystorePassword != "new" {
		t.Fatalf("keystorePassword = %q after the change, want %q", m.keystorePassword, "new")
	}

	m.pwdMode = 4
	m, _ = typeAndEnter(t, m, "old")
	if m.backupMode {
		t.Fatal("the old password still opened the backup")
	}
	m.pwdMode = 4
	m, _ = typeAndEnter(t, m, "new")
	if !m.backupMode {
		t.Fatal("the new password didn't open the backup")
	}
}
