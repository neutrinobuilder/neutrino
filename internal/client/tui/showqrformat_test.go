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

// TestHandleInputShowQREntersFormatChoice verifies "/show-qr" only opens
// the format picker, like `neutrino show-qr`'s CLI prompt, it must never
// jump straight to the animated QR.
func TestHandleInputShowQREntersFormatChoice(t *testing.T) {
	m := &model{}
	cmd := m.handleInput("/show-qr")
	if !m.showQRFormatMode {
		t.Fatal("expected showQRFormatMode to be true")
	}
	if m.showQRFormatIdx != 0 {
		t.Fatalf("expected default idx 0 (image), got %d", m.showQRFormatIdx)
	}
	if cmd != nil {
		t.Fatal("expected a nil cmd while only opening the picker")
	}
}

// TestShowQRFormatEnterImageCallsSaveIdentityQR verifies confirming the
// default choice (idx 0, "image") calls the SaveIdentityQR closure and
// never the animated flow.
func TestShowQRFormatEnterImageCallsSaveIdentityQR(t *testing.T) {
	called := false
	m := model{
		showQRFormatMode: true,
		showQRFormatIdx:  0,
		saveIdentityQR: func() ([]string, error) {
			called = true
			return []string{"/tmp/a.txt", "/tmp/a-part1.png"}, nil
		},
	}
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	fm := newModel.(model)
	if fm.showQRFormatMode {
		t.Fatal("expected showQRFormatMode to be cleared")
	}
	if cmd != nil {
		t.Fatal(cmd())
	}
	if !called {
		t.Fatal("expected SaveIdentityQR to be called")
	}
	if !fm.textPopupMode {
		t.Fatal("expected a result popup to open")
	}
}

// TestShowQRFormatEnterVideoCallsCmdShowQR verifies toggling to idx 1
// ("animated") and confirming goes through cmdShowQR, never
// SaveIdentityQR.
func TestShowQRFormatEnterVideoCallsCmdShowQR(t *testing.T) {
	saveCalled := false
	m := model{
		showQRFormatMode: true,
		showQRFormatIdx:  0,
		myUsername:       "alice",
		myIdentityPub:    []byte("identity-pub-bytes"),
		saveIdentityQR: func() ([]string, error) {
			saveCalled = true
			return nil, nil
		},
	}
	toggled, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	tm := toggled.(model)
	if tm.showQRFormatIdx != 1 {
		t.Fatalf("expected idx to toggle to 1, got %d", tm.showQRFormatIdx)
	}
	newModel, cmd := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	fm := newModel.(model)
	if fm.showQRFormatMode {
		t.Fatal("expected showQRFormatMode to be cleared")
	}
	if saveCalled {
		t.Fatal("expected SaveIdentityQR NOT to be called for the animated choice")
	}
	if cmd == nil {
		t.Fatal("expected a non-nil cmd starting the animated QR")
	}
}

// TestShowQRFormatEscCancels verifies Esc cancels without calling
// either path.
func TestShowQRFormatEscCancels(t *testing.T) {
	called := false
	m := model{
		showQRFormatMode: true,
		saveIdentityQR:   func() ([]string, error) { called = true; return nil, nil },
	}
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	fm := newModel.(model)
	if fm.showQRFormatMode {
		t.Fatal("expected showQRFormatMode to be cleared")
	}
	if cmd != nil {
		t.Fatal("expected a nil cmd on Esc")
	}
	if called {
		t.Fatal("expected SaveIdentityQR NOT to be called on cancel")
	}
}
