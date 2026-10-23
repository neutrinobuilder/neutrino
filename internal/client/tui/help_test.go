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
)

// TestHelpPagingVisitsEveryCommand verifies that PgDn in the /help popup
// moves to the entry right after the last one shown — contiguous pages
// covering every command — and PgUp walks the same pages back.
func TestHelpPagingVisitsEveryCommand(t *testing.T) {
	for _, size := range []struct{ w, h int }{{80, 24}, {160, 50}, {40, 12}} {
		m := model{lastTermW: size.w, lastTermH: size.h, helpMode: true}
		total := len(client.CommandList())
		var starts []int
		for {
			starts = append(starts, m.helpScroll)
			end := m.helpPageEnd(m.helpScroll)
			if end <= m.helpScroll {
				t.Fatalf("%dx%d: empty page at %d", size.w, size.h, m.helpScroll)
			}
			next, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
			m = next.(model)
			if end >= total {
				if m.helpScroll != starts[len(starts)-1] {
					t.Fatalf("%dx%d: PgDn on the last page moved to %d", size.w, size.h, m.helpScroll)
				}
				break
			}
			if m.helpScroll != end {
				t.Fatalf("%dx%d: PgDn from %d went to %d, want %d (the entry after the page)", size.w, size.h, starts[len(starts)-1], m.helpScroll, end)
			}
		}
		for i := len(starts) - 2; i >= 0; i-- {
			next, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
			m = next.(model)
			if m.helpScroll != starts[i] {
				t.Fatalf("%dx%d: PgUp went to %d, want %d", size.w, size.h, m.helpScroll, starts[i])
			}
		}
	}
}
