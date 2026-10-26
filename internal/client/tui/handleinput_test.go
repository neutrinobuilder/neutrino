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
	"fmt"
	"strings"
	"testing"

	"neutrino/internal/client"
	"neutrino/internal/i18n"
	"neutrino/internal/shared"
)

// TestMistypedCommandNeverSentAsMessage verifies that a command typed in
// the wrong form inside a room, an argument to a command that takes
// none, or a missing required argument, is reported in Console and
// never sent to the room as a chat message.
func TestMistypedCommandNeverSentAsMessage(t *testing.T) {
	noArgs := func(name string) string { return fmt.Sprintf(i18n.T("tui.err_command_no_args"), name) }
	cases := []struct{ input, want string }{
		{"/sec-backup now", noArgs("/sec-backup")},
		{"/sec-passwd secret", noArgs("/sec-passwd")},
		{"/nukex please", noArgs("/nukex")},
		{"/quit later", noArgs("/quit")},
		{"/help commands", noArgs("/help")},
		{"/grp-sav team", fmt.Sprintf(i18n.T("tui.err_unknown_command"), "/grp-sav")},
		{"/grp-save", i18n.T("tui.err_usage_save_group")},
		{"/cnt-add", strings.Split(i18n.T("tui.err_usage_add_contact"), "\n")[0]},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			cli := client.New("127.0.0.1", 0, "alice", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
			m := &model{
				tabs:   []*roomTab{{isConsole: true}, {name: "room", cli: cli, groupID: "g"}},
				active: 1,
			}
			cmd := m.handleInput(c.input)
			if cmd == nil {
				t.Fatal("expected a Console error")
			}
			msg, ok := cmd().(localDisplayMsg)
			if !ok {
				t.Fatalf("got %T, want a localDisplayMsg (the input was handled as a chat message)", cmd())
			}
			if msg.tabIdx != m.consoleIdx || !msg.isError || !strings.Contains(msg.text, c.want) {
				t.Errorf("got %+v, want a Console error containing %q", msg, c.want)
			}
		})
	}
}
