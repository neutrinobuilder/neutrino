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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"neutrino/internal/client"
	"neutrino/internal/i18n"
	"neutrino/internal/keystore"
	"neutrino/internal/server"
	"neutrino/internal/shared"
)

// cmdMsgText runs a non-nil tea.Cmd and extracts the text of a localDisplayMsg —
// shared helper for every test on commands that return a synchronous message.
func cmdMsgText(t *testing.T, cmd tea.Cmd) string {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a non-nil tea.Cmd")
	}
	ld, ok := cmd().(localDisplayMsg)
	if !ok {
		t.Fatalf("expected localDisplayMsg, got %T", ld)
	}
	return ld.text
}

// newTestWSConn starts a minimal test WS server (accepts and reads until the
// client closes, same pattern as internal/server/hub_test.go) and returns
// the client-side connection, ready to be assigned to client.Client.Conn.
// A copy of the same-named helper in internal/client/client_test.go —
// duplicated here because the two test packages cannot share unexported
// functions with each other.
func newTestWSConn(t *testing.T) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// newTestClient builds a minimal Client (no network connection: client.New()
// only generates in-memory keys) with its members registered via
// RegisterUser — each under testPub(username) as identity key — so
// LookupMemberKey/LookupUsername behave as on an already-authenticated
// real WS session.
func newTestClient(registered map[string]string) *client.Client {
	c := client.New("127.0.0.1", 0, "self", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	for userID, username := range registered {
		c.RegisterUser(userID, username, testPub(username))
	}
	return c
}

func TestApplyGroupMemberAdded(t *testing.T) {
	cli := newTestClient(map[string]string{
		"uid-host": "alice",
		"uid-eve":  "eve",
	})
	m := &model{}

	newTab := func() *roomTab {
		return &roomTab{
			hostKey:      testKey("alice"),
			cli:          cli,
			groupMembers: []GroupMember{{Username: "alice", IdentityPub: testPub("alice")}, {Username: "bob", IdentityPub: testPub("bob")}},
		}
	}

	t.Run("accepted from host adds member and returns a system line", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{
			Member: shared.MemberInfo{Username: "dave", IdentityPub: testPub("dave")},
		})

		line := m.applyGroupMemberAdded(tab, "uid-host", "12:00", string(payload))

		if line == nil || !line.isSystem {
			t.Fatalf("expected a system chatLine, got %+v", line)
		}
		found := false
		for _, mb := range tab.groupMembers {
			if mb.Username == "dave" {
				found = true
			}
		}
		if !found {
			t.Error("dave was not added to tab.groupMembers")
		}
	})

	t.Run("rejected from a non-host sender (anti-spoofing)", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{
			Member: shared.MemberInfo{Username: "mallory", IdentityPub: testPub("mallory")},
		})

		line := m.applyGroupMemberAdded(tab, "uid-eve", "12:00", string(payload))

		if line != nil {
			t.Fatalf("expected nil (announcement discarded), got %+v", line)
		}
		for _, mb := range tab.groupMembers {
			if mb.Username == "mallory" {
				t.Fatal("mallory was added: a non-host member was able to change the group membership")
			}
		}
	})

	t.Run("rejected from an unresolvable sender", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{
			Member: shared.MemberInfo{Username: "zack", IdentityPub: testPub("zack")},
		})

		line := m.applyGroupMemberAdded(tab, "uid-unregistered", "12:00", string(payload))

		if line != nil {
			t.Fatalf("expected nil for unresolvable sender, got %+v", line)
		}
	})

	t.Run("idempotent when the member is already present", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{
			Member: shared.MemberInfo{Username: "bob", IdentityPub: testPub("bob")},
		})

		line := m.applyGroupMemberAdded(tab, "uid-host", "12:00", string(payload))

		if line != nil {
			t.Fatalf("expected nil for an already-present member, got %+v", line)
		}
		if len(tab.groupMembers) != 2 {
			t.Fatalf("expected no duplicate, got %d members", len(tab.groupMembers))
		}
	})

	t.Run("a homonym with a different key is a new member", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{
			Member: shared.MemberInfo{Username: "bob", IdentityPub: testPub("another-bob")},
		})

		if line := m.applyGroupMemberAdded(tab, "uid-host", "12:00", string(payload)); line == nil {
			t.Fatal("a second bob with a different key must be added")
		}
		if len(tab.groupMembers) != 3 {
			t.Fatalf("expected 3 members, got %d", len(tab.groupMembers))
		}
	})

	t.Run("invalid JSON is ignored", func(t *testing.T) {
		tab := newTab()

		line := m.applyGroupMemberAdded(tab, "uid-host", "12:00", "not json")

		if line != nil {
			t.Fatalf("expected nil for invalid payload, got %+v", line)
		}
	})

	t.Run("empty member username is ignored", func(t *testing.T) {
		tab := newTab()
		payload, _ := json.Marshal(groupMemberAddedPayload{Member: shared.MemberInfo{Username: ""}})

		line := m.applyGroupMemberAdded(tab, "uid-host", "12:00", string(payload))

		if line != nil {
			t.Fatalf("expected nil for empty username, got %+v", line)
		}
	})
}

// TestCmdAddMemberGuards covers the synchronous checks of cmdAddMember (host-only,
// rejection on a two-member chat (ratchet DH), missing room secret, empty argument, contact not
// found, contact already a member) — all resolved before generating a secret or sending a
// knock, so verifiable without network. The positive path (knock + broadcast) is not
// covered here: it requires real Tor/HTTP.
func TestCmdAddMemberGuards(t *testing.T) {
	baseContacts := []ContactInfo{
		{Username: "bob", IdentityPub: testPub("bob")},
		{Username: "carol", IdentityPub: testPub("carol")},
	}

	newHostModel := func(ratchet, tor bool, roomSecret []byte) *model {
		cli := client.New("127.0.0.1", 0, "alice", nil, ratchet, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
		if tor {
			cli.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("not used in this test")
			})
		}
		tab := &roomTab{
			groupID:      "g1",
			cli:          cli,
			roomSecret:   roomSecret,
			groupMembers: []GroupMember{{Username: "alice", IdentityPub: testPub("alice")}, {Username: "bob", IdentityPub: testPub("bob")}},
		}
		return &model{
			tabs:       []*roomTab{tab},
			active:     0,
			consoleIdx: 1,
			contacts:   baseContacts,
		}
	}

	msgText := cmdMsgText

	t.Run("refused outside a group tab", func(t *testing.T) {
		m := newHostModel(false, false, []byte("secret"))
		m.tabs[0].groupID = ""
		text := msgText(t, m.cmdAddMember("bob"))
		if !strings.Contains(text, i18n.T("tui.err_add_member_host_only")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused when connected via Tor (not host)", func(t *testing.T) {
		m := newHostModel(false, true, []byte("secret"))
		text := msgText(t, m.cmdAddMember("bob"))
		if !strings.Contains(text, i18n.T("tui.err_add_member_host_only")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused on a two-member ratchet DH room", func(t *testing.T) {
		m := newHostModel(true, false, []byte("secret"))
		text := msgText(t, m.cmdAddMember("bob"))
		if !strings.Contains(text, i18n.T("tui.err_add_member_ratchet_dh")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused without a room secret", func(t *testing.T) {
		m := newHostModel(false, false, nil)
		text := msgText(t, m.cmdAddMember("bob"))
		if !strings.Contains(text, i18n.T("tui.err_room_secret_unavailable")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused with an empty argument", func(t *testing.T) {
		m := newHostModel(false, false, []byte("secret"))
		text := msgText(t, m.cmdAddMember(""))
		if !strings.Contains(text, i18n.T("tui.err_usage_add_member")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("opens the picker for an unknown contact instead of erroring", func(t *testing.T) {
		m := newHostModel(false, false, []byte("secret"))
		if cmd := m.cmdAddMember("zzz"); cmd != nil {
			t.Fatalf("expected nil tea.Cmd (picker opened), got a command")
		}
		if !m.contactPickerMode || m.contactPickerCmd != client.CmdAddMember || m.contactPickerFilter != "zzz" {
			t.Errorf("expected picker open for client.CmdAddMember filtered on %q, got mode=%v cmd=%v filter=%q",
				"zzz", m.contactPickerMode, m.contactPickerCmd, m.contactPickerFilter)
		}
	})

	t.Run("refused for a contact already in the group", func(t *testing.T) {
		m := newHostModel(false, false, []byte("secret"))
		text := msgText(t, m.cmdAddMember("bob"))
		if !strings.Contains(text, "already a member of this group") {
			t.Errorf("got %q", text)
		}
	})
}

// TestCmdReinviteGuards covers the same synchronous checks as cmdReinvite (host-only,
// missing room secret, empty argument, member not found) plus looking up the
// member by username (case-insensitive) and by local contact-book name — all resolved
// before sending the knock, so verifiable without network.
func TestCmdReinviteGuards(t *testing.T) {
	baseContacts := []ContactInfo{
		{
			Username:    "bob",
			LocalName:   "Bobby",
			IdentityPub: testPub("bob"),
			Devices: map[string]*keystore.DeviceRelation{
				"d": {
					RelIdentityPriv:            make([]byte, ed25519.PrivateKeySize),
					PeerRelIdentityPub:         make([]byte, ed25519.PublicKeySize),
					RelIdentityConfirmedByPeer: true,
					RelContentConfirmedByPeer:  true,
					Address:                    "bobaddr.onion",
				},
			},
		},
	}
	defaultMembers := []GroupMember{{Username: "alice", IdentityPub: testPub("alice")}, {Username: "bob", IdentityPub: testPub("bob")}}

	newHostModel := func(tor bool, roomSecret []byte, groupMembers []GroupMember) *model {
		cli := client.New("127.0.0.1", 0, "alice", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
		if tor {
			cli.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("not used in this test")
			})
		}
		tab := &roomTab{
			groupID:      "g1",
			cli:          cli,
			roomSecret:   roomSecret,
			groupMembers: groupMembers,
		}
		tab.setGroupLabels()
		return &model{
			tabs:          []*roomTab{tab},
			active:        0,
			consoleIdx:    1,
			contacts:      baseContacts,
			myUsername:    "alice",
			myIdentityPub: testPub("alice"),
			replaceRoomSecret: func(roomID string, oldSecret, newSecret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
			},
		}
	}

	msgText := cmdMsgText

	t.Run("refused outside a group tab", func(t *testing.T) {
		m := newHostModel(false, []byte("secret"), defaultMembers)
		m.tabs[0].groupID = ""
		text := msgText(t, m.cmdReinvite("bob"))
		if !strings.Contains(text, i18n.T("tui.err_reinvite_host_only")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused when connected via Tor (not host)", func(t *testing.T) {
		m := newHostModel(true, []byte("secret"), defaultMembers)
		text := msgText(t, m.cmdReinvite("bob"))
		if !strings.Contains(text, i18n.T("tui.err_reinvite_host_only")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused without a room secret", func(t *testing.T) {
		m := newHostModel(false, nil, defaultMembers)
		text := msgText(t, m.cmdReinvite("bob"))
		if !strings.Contains(text, i18n.T("tui.err_room_secret_unavailable")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused with an empty argument", func(t *testing.T) {
		m := newHostModel(false, []byte("secret"), defaultMembers)
		text := msgText(t, m.cmdReinvite(""))
		if !strings.Contains(text, i18n.T("tui.err_usage_reinvite")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("opens the picker for a name not in the group instead of erroring", func(t *testing.T) {
		m := newHostModel(false, []byte("secret"), defaultMembers)
		if cmd := m.cmdReinvite("zzz"); cmd != nil {
			t.Fatalf("expected nil tea.Cmd (picker opened), got a command")
		}
		if !m.contactPickerMode || m.contactPickerCmd != client.CmdReinvite || m.contactPickerFilter != "zzz" {
			t.Errorf("expected picker open for client.CmdReinvite filtered on %q, got mode=%v cmd=%v filter=%q",
				"zzz", m.contactPickerMode, m.contactPickerCmd, m.contactPickerFilter)
		}
	})

	t.Run("matches an existing member case-insensitively by username", func(t *testing.T) {
		m := newHostModel(false, []byte("secret"), append([]GroupMember{}, defaultMembers...))
		if cmd := m.cmdReinvite("BOB"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		if _, ok := m.tabs[0].secretsByMember[testKey("bob")]; !ok {
			t.Error("expected a new secret to be registered for bob")
		}
	})

	t.Run("matches an existing member by local name", func(t *testing.T) {
		m := newHostModel(false, []byte("secret"), append([]GroupMember{}, defaultMembers...))
		if cmd := m.cmdReinvite("Bobby"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		if _, ok := m.tabs[0].secretsByMember[testKey("bob")]; !ok {
			t.Error("expected a new secret to be registered for bob")
		}
	})
}

// cmdMsgTexts flattens a tea.Cmd (including a tea.Batch of several commands, like
// the one returned by cmdDelContact) and extracts the text of every
// resulting localDisplayMsg.
func cmdMsgTexts(t *testing.T, cmd tea.Cmd) []string {
	t.Helper()
	if cmd == nil {
		return nil
	}
	var out []string
	var flatten func(c tea.Cmd)
	flatten = func(c tea.Cmd) {
		if c == nil {
			return
		}
		switch msg := c().(type) {
		case tea.BatchMsg:
			for _, sub := range msg {
				flatten(sub)
			}
		case localDisplayMsg:
			out = append(out, msg.text)
		case probeResultMsg:
			// cmdActiveSilent()/probeContacts() with a nil dialTor (never the case
			// in production, always the case in these minimal test models) returns
			// an empty probeResultMsg — only to close out m.probing's loop,
			// never text to extract. See probeContacts.
		default:
			t.Fatalf("expected localDisplayMsg or tea.BatchMsg, got %T", msg)
		}
	}
	flatten(cmd)
	return out
}

// TestCmdDelContactRevokesRoomAccess verifies that deleting a contact silently
// revokes its access to every already-open room where we were host and it was
// a member, BEFORE removing it from the contact book — not just deleting it
// from the contact book while leaving its room secrets still valid.
func TestCmdDelContactRevokesRoomAccess(t *testing.T) {
	newBaseContact := func() ContactInfo {
		return ContactInfo{
			Username:    "bob",
			LocalName:   "Bobby",
			IdentityPub: testPub("bob"),
		}
	}

	t.Run("revokes secrets in every host tab where the contact is a member, then deletes it", func(t *testing.T) {
		var banned []string
		var deleted []byte
		tab := &roomTab{
			groupID: "g1",
			cli:     client.New("127.0.0.1", 0, "alice", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{}),
			online:  []string{testKey("bob")},
			secretsByMember: map[string]map[string][]byte{
				testKey("bob"): {"dev1": []byte("secret1")},
			},
		}
		m := &model{
			tabs:       []*roomTab{tab},
			active:     0,
			consoleIdx: 1,
			contacts:   []ContactInfo{newBaseContact()},
			banMember: func(roomID string, secret []byte, userID string) bool {
				banned = append(banned, string(secret))
				return false
			},
			deleteContact: func(pub []byte) error {
				deleted = pub
				return nil
			},
		}

		texts := cmdMsgTexts(t, m.cmdDelContact("bob"))

		if len(banned) != 1 || banned[0] != "secret1" {
			t.Errorf("expected the room secret to be revoked, got %v", banned)
		}
		if _, ok := tab.secretsByMember[testKey("bob")]; ok {
			t.Error("expected secretsByMember[bob] to be removed from the tab")
		}
		if deleted == nil {
			t.Error("expected deleteContact to be called")
		}
		if len(m.contacts) != 0 {
			t.Errorf("expected the contact to be removed from m.contacts, got %v", m.contacts)
		}
		if len(texts) != 2 {
			t.Fatalf("expected 2 messages (room revocation + contact_removed), got %v", texts)
		}
		wantBan := fmt.Sprintf(i18n.T("tui.ban_done_offline"), "Bobby (bob)")
		if !strings.Contains(texts[0], wantBan) {
			t.Errorf("expected the first message to be the room revocation (%q), got %q", wantBan, texts[0])
		}
		wantRemoved := fmt.Sprintf(i18n.T("tui.contact_removed"), "Bobby (bob)")
		if texts[1] != wantRemoved {
			t.Errorf("expected the final message to be %q, got %q", wantRemoved, texts[1])
		}
	})

	t.Run("no room to revoke: only the contact_removed message is returned", func(t *testing.T) {
		tab := &roomTab{groupID: "g1", secretsByMember: map[string]map[string][]byte{}}
		var deleted []byte
		m := &model{
			tabs:       []*roomTab{tab},
			active:     0,
			consoleIdx: 1,
			contacts:   []ContactInfo{newBaseContact()},
			banMember: func(roomID string, secret []byte, userID string) bool {
				t.Fatal("banMember should not be called: contact is not a member of any open room")
				return false
			},
			deleteContact: func(pub []byte) error {
				deleted = pub
				return nil
			},
		}

		texts := cmdMsgTexts(t, m.cmdDelContact("bob"))

		if deleted == nil {
			t.Error("expected deleteContact to be called")
		}
		if len(texts) != 1 {
			t.Fatalf("expected only the contact_removed message, got %v", texts)
		}
	})
}

func TestPadName(t *testing.T) {
	cases := []struct {
		name  string
		s     string
		width int
		want  string
	}{
		{"shorter than width is right-padded", "bob", 6, "bob   "},
		{"exact width is unchanged", "alice1", 6, "alice1"},
		{"longer than width is truncated", "alexandria", 6, "alexan"},
		{"empty string is all padding", "", 4, "    "},
		{"zero width truncates to empty", "bob", 0, ""},
		{"multi-byte runes count as one column each", "naïve", 5, "naïve"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := padName(c.s, c.width); got != c.want {
				t.Errorf("padName(%q, %d) = %q, want %q", c.s, c.width, got, c.want)
			}
		})
	}
}

// TestRenderTabBarSlidingWindow verifies that with more than a handful of open
// tabs on a narrow terminal, where the full bar does not fit, a sliding window
// keeps the active tab visible instead of letting it scroll off screen with no
// indication of where it is.
func TestRenderTabBarSlidingWindow(t *testing.T) {
	mkTabs := func(names ...string) []*roomTab {
		tabs := make([]*roomTab, len(names))
		for i, n := range names {
			tabs[i] = &roomTab{name: n}
		}
		return tabs
	}

	t.Run("all tabs fit: no indicators", func(t *testing.T) {
		m := model{tabs: mkTabs("one", "two", "three"), active: 1, myUsername: "alice"}
		m.vp.Width = 80
		out := m.renderTabBar()
		if strings.ContainsAny(out, "‹›") {
			t.Errorf("no arrows expected when every tab fits: %q", out)
		}
		for _, n := range []string{"one", "two", "three"} {
			if !strings.Contains(out, n) {
				t.Errorf("want tab %q in the bar, got %q", n, out)
			}
		}
	})

	t.Run("too many tabs: active at the end stays visible, arrow on the left only", func(t *testing.T) {
		names := []string{"one", "two", "three", "four", "five"}
		m := model{tabs: mkTabs(names...), active: 4, myUsername: "alice"} // "five", the last one
		m.vp.Width = 20                                                    // narrow: not all 5 fit
		out := m.renderTabBar()
		if !strings.Contains(out, "five") {
			t.Fatalf("the active tab must stay visible, got %q", out)
		}
		if !strings.Contains(out, "‹") {
			t.Errorf("want the ‹ indicator for tabs hidden on the left, got %q", out)
		}
		if strings.Contains(out, "›") {
			t.Errorf("no tab hidden on the right: › not expected, got %q", out)
		}
		if w := lipgloss.Width(out); w > m.vp.Width {
			t.Errorf("resulting width %d exceeds the available width %d: %q", w, m.vp.Width, out)
		}
	})

	t.Run("active tab in the middle: the window follows it", func(t *testing.T) {
		names := []string{"one", "two", "three", "four", "five"}
		m := model{tabs: mkTabs(names...), active: 2, myUsername: "alice"} // "three", in the middle
		m.vp.Width = 20
		out := m.renderTabBar()
		if !strings.Contains(out, "three") {
			t.Fatalf("the active tab must stay visible, got %q", out)
		}
		if w := lipgloss.Width(out); w > m.vp.Width {
			t.Errorf("resulting width %d exceeds the available width %d: %q", w, m.vp.Width, out)
		}
	})

	// The "fake tab" holding the active identity is never a real tab (no index
	// in m.tabs): unlike real tabs, it must never end up hidden by the sliding
	// window, under any width condition.
	t.Run("identity prefix always visible, even when not every tab fits", func(t *testing.T) {
		names := []string{"one", "two", "three", "four", "five"}
		m := model{tabs: mkTabs(names...), active: 4, myUsername: "alice"}
		m.vp.Width = 20
		out := m.renderTabBar()
		if !strings.Contains(out, "alice:") {
			t.Fatalf("want the identity prefix \"alice:\" always visible, got %q", out)
		}
		if !strings.Contains(out, "five") {
			t.Fatalf("the active tab must stay visible, got %q", out)
		}
		if w := lipgloss.Width(out); w > m.vp.Width {
			t.Errorf("resulting width %d exceeds the available width %d: %q", w, m.vp.Width, out)
		}
	})
}

func TestResolveNameOrPickerKey(t *testing.T) {
	m := &model{
		contacts: []ContactInfo{
			{Username: "bob", LocalName: "Bobby"},
			{Username: "carol"},
		},
	}

	t.Run("matches by local name", func(t *testing.T) {
		c := m.resolveNameOrPickerKey("Bobby")
		if c == nil || c.Username != "bob" {
			t.Fatalf("expected to resolve bob via local name, got %+v", c)
		}
	})

	t.Run("matches by username when no local name is set", func(t *testing.T) {
		c := m.resolveNameOrPickerKey("carol")
		if c == nil || c.Username != "carol" {
			t.Fatalf("expected to resolve carol via username, got %+v", c)
		}
	})

	t.Run("username also resolves a contact that has a local name", func(t *testing.T) {
		c := m.resolveNameOrPickerKey("bob")
		if c == nil || c.Username != "bob" {
			t.Fatalf("expected to resolve bob via username, got %+v", c)
		}
	})

	t.Run("unknown name returns nil", func(t *testing.T) {
		if c := m.resolveNameOrPickerKey("zzz"); c != nil {
			t.Fatalf("expected nil, got %+v", c)
		}
	})
}

// TestHasPersistentContentRel verifies that a SAVED contact (resolveContactByPub != nil)
// that never completed the rel_init handshake must not count as an "already usable
// relationship" — only the presence of BOTH keys (our RelContentPriv, its
// non-revoked PeerRelContentPub) does.
func TestHasPersistentContentRel(t *testing.T) {
	t.Run("unknown contact", func(t *testing.T) {
		m := &model{}
		if m.hasPersistentContentRel(testKey("bob")) {
			t.Fatal("no saved contact: must never be true")
		}
	})

	t.Run("known contact without any device keys", func(t *testing.T) {
		m := &model{contacts: []ContactInfo{{Username: "bob", IdentityPub: testPub("bob")}}}
		if m.hasPersistentContentRel(testKey("bob")) {
			t.Fatal("known contact but handshake never completed: must not be true")
		}
	})

	t.Run("known contact with only my key", func(t *testing.T) {
		m := &model{contacts: []ContactInfo{{Username: "bob", IdentityPub: testPub("bob"), Devices: map[string]*keystore.DeviceRelation{
			"dev1": {RelContentPriv: make([]byte, ed25519.PrivateKeySize)},
		}}}}
		if m.hasPersistentContentRel(testKey("bob")) {
			t.Fatal("the peer's public key is missing: must not be true")
		}
	})

	t.Run("known contact with revoked peer key", func(t *testing.T) {
		m := &model{contacts: []ContactInfo{{Username: "bob", IdentityPub: testPub("bob"), Devices: map[string]*keystore.DeviceRelation{
			"dev1": {
				RelContentPriv:    make([]byte, ed25519.PrivateKeySize),
				PeerRelContentPub: make([]byte, ed25519.PublicKeySize),
				RevokedContent:    true,
			},
		}}}}
		if m.hasPersistentContentRel(testKey("bob")) {
			t.Fatal("the peer's key is revoked: must not be true")
		}
	})

	t.Run("known contact with both keys established", func(t *testing.T) {
		m := &model{contacts: []ContactInfo{{Username: "bob", IdentityPub: testPub("bob"), Devices: map[string]*keystore.DeviceRelation{
			"dev1": {
				RelContentPriv:    make([]byte, ed25519.PrivateKeySize),
				PeerRelContentPub: make([]byte, ed25519.PublicKeySize),
			},
		}}}}
		if !m.hasPersistentContentRel(testKey("bob")) {
			t.Fatal("both keys present and not revoked: must be true")
		}
	})
}

// TestCmdInvite covers the core cryptographic invariant the /grp-add-member guard
// relies on: a room created with exactly 2 total members (me + one invitee) starts
// in ratchet DH mode, one with 3+ starts in SenderKey mode — decided once here,
// never recomputed. The error path (usage, contacts not found) and per-member
// secret registration are verified together, without running the network knock
// (the returned tea.Cmd is never invoked).
func TestCmdInvite(t *testing.T) {
	baseContacts := []ContactInfo{
		{
			Username:    "bob",
			IdentityPub: testPub("bob"),
			Devices: map[string]*keystore.DeviceRelation{
				"d": {
					RelIdentityPriv:            make([]byte, ed25519.PrivateKeySize),
					PeerRelIdentityPub:         make([]byte, ed25519.PublicKeySize),
					RelIdentityConfirmedByPeer: true,
					RelContentConfirmedByPeer:  true,
					Address:                    "bobaddr.onion",
				},
			},
		},
		{
			Username:    "carol",
			IdentityPub: testPub("carol"),
			Devices: map[string]*keystore.DeviceRelation{
				"d": {
					RelIdentityPriv:            make([]byte, ed25519.PrivateKeySize),
					PeerRelIdentityPub:         make([]byte, ed25519.PublicKeySize),
					RelIdentityConfirmedByPeer: true,
					RelContentConfirmedByPeer:  true,
					Address:                    "carolladdr.onion",
				},
			},
		},
	}

	newModel := func() *model {
		return &model{
			myUsername:    "alice",
			myIdentityPub: testPub("alice"),
			contacts:      baseContacts,
			addRoom: func(roomID string, secret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
			},
			inviteTimeout: time.Second,
		}
	}

	t.Run("refused with no arguments", func(t *testing.T) {
		m := newModel()
		text := cmdMsgText(t, m.cmdInvite(""))
		if !strings.Contains(text, i18n.T("tui.err_usage_invite")) {
			t.Errorf("got %q", text)
		}
	})

	t.Run("refused when a contact is not found", func(t *testing.T) {
		m := newModel()
		text := cmdMsgText(t, m.cmdInvite("bob zzz"))
		if !strings.Contains(text, "zzz") {
			t.Errorf("expected the missing contact name in the error, got %q", text)
		}
		if len(m.tabs) != 0 {
			t.Errorf("expected no tab to be created on error, got %d", len(m.tabs))
		}
	})

	t.Run("inviting exactly one contact creates a two-member ratchet DH room", func(t *testing.T) {
		m := newModel()
		if cmd := m.cmdInvite("bob"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		if len(m.tabs) != 1 {
			t.Fatalf("expected 1 tab to be created, got %d", len(m.tabs))
		}
		tab := m.tabs[0]
		if !tab.cli.RatchetDH() {
			t.Error("expected ratchet DH to be active for a 2-member room")
		}
		if len(tab.groupMembers) != 2 {
			t.Errorf("expected 2 group members, got %d", len(tab.groupMembers))
		}
	})

	t.Run("inviting two or more contacts creates a SenderKey group (no ratchet)", func(t *testing.T) {
		m := newModel()
		if cmd := m.cmdInvite("bob carol"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		tab := m.tabs[0]
		if tab.cli.RatchetDH() {
			t.Error("expected ratchet DH to be inactive for a 3-member room")
		}
		if len(tab.groupMembers) != 3 {
			t.Errorf("expected 3 group members, got %d", len(tab.groupMembers))
		}
		for _, want := range []string{"alice", "bob", "carol"} {
			if _, ok := tab.secretsByMember[testKey(want)]; !ok {
				t.Errorf("expected a registered secret for %s", want)
			}
		}
	})
}

// TestCmdInviteQueuesPendingContactAndRetriesOnceReady verifies that inviting a
// mix of ready and not-ready contacts does not fail outright — the invite is
// queued (queuePendingInvite) and retried on its own (retryPendingInvites) as
// soon as the not-ready contact confirms BOTH relationship keys (simulated here
// without going through a real rel_init_ack, which is tested separately in
// applyRelInit).
func TestCmdInviteQueuesPendingContactAndRetriesOnceReady(t *testing.T) {
	bobPub := testPub("bob")
	carolPub := testPub("carol")
	contacts := []ContactInfo{
		{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {
					RelIdentityPriv:            make([]byte, ed25519.PrivateKeySize),
					PeerRelIdentityPub:         make([]byte, ed25519.PublicKeySize),
					RelIdentityConfirmedByPeer: true,
					RelContentConfirmedByPeer:  true,
					Address:                    "bobaddr.onion",
				},
			},
		},
		{
			Username:    "carol",
			IdentityPub: carolPub,
			Devices: map[string]*keystore.DeviceRelation{
				// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer remain
				// false — carol is not ready yet.
				"d": {
					RelIdentityPriv:    make([]byte, ed25519.PrivateKeySize),
					PeerRelIdentityPub: make([]byte, ed25519.PublicKeySize),
					Address:            "carolladdr.onion",
				},
			},
		},
	}
	m := &model{
		myUsername:    "alice",
		myIdentityPub: testPub("alice"),
		contacts:      contacts,
		addRoom: func(roomID string, secret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
		},
		inviteTimeout: time.Minute,
		consoleIdx:    1,
	}

	texts := cmdMsgTexts(t, m.cmdInvite("bob carol"))
	found := false
	for _, txt := range texts {
		if strings.Contains(txt, "carol") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a queued-invite notice mentioning carol, got %v", texts)
	}
	if len(m.tabs) != 0 {
		t.Fatalf("expected no tab created yet (carol not ready), got %d", len(m.tabs))
	}
	if len(m.pendingInvites) != 1 {
		t.Fatalf("expected exactly one queued invite, got %d", len(m.pendingInvites))
	}
	if !m.pendingInvites[0].pending[testKey("carol")] {
		t.Error("expected carol to be in the pending set of the queued invite")
	}

	// Carol becomes ready (equivalent to a rel_init_ack just applied) —
	// retryPendingInvites must restart the invite on its own, synchronously.
	dev := contacts[1].Devices["d"]
	dev.RelIdentityConfirmedByPeer = true
	dev.RelContentConfirmedByPeer = true

	if cmd := m.retryPendingInvites(carolPub); cmd == nil {
		t.Fatal("expected a non-nil retry cmd once carol becomes ready")
	}
	if len(m.pendingInvites) != 0 {
		t.Errorf("expected the queue to be drained after the retry, got %d entries left", len(m.pendingInvites))
	}
	if len(m.tabs) != 1 {
		t.Fatalf("expected the invite to have been retried and a tab created, got %d tabs", len(m.tabs))
	}
	if len(m.tabs[0].groupMembers) != 3 {
		t.Errorf("expected 3 group members (alice, bob, carol) after the retry, got %d", len(m.tabs[0].groupMembers))
	}
}

// TestPendingInvitesExpireOnProbeSweep verifies that a queued invite expiring:
// the periodic probe cycle (case probeResultMsg, Update()) drops any invite
// whose deadline has already passed — never a retry, only a notice in the
// Console — reusing the same inviteTimeout instead of a dedicated ticker.
func TestPendingInvitesExpireOnProbeSweep(t *testing.T) {
	m := model{
		consoleIdx: 0,
		pendingInvites: []*pendingInvite{
			{
				label:   "test-label",
				pending: map[string]bool{"carol": true},
				retry: func(*model) tea.Cmd {
					t.Error("retry must never run on an expired invite")
					return nil
				},
				deadline: time.Now().Add(-time.Minute), // already expired
			},
		},
	}
	mm, cmd := m.Update(probeResultMsg{silent: true})
	m2 := mm.(model)
	if len(m2.pendingInvites) != 0 {
		t.Fatalf("expected the expired invite to be dropped, got %d left", len(m2.pendingInvites))
	}
	texts := cmdMsgTexts(t, cmd)
	found := false
	for _, txt := range texts {
		if strings.Contains(txt, "test-label") && strings.Contains(txt, "carol") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a timeout notice mentioning the label and carol, got %v", texts)
	}
}

// TestProbeResultAppliesGeneratedRelKeysToEmptyDevices verifies that a contact
// with an empty Devices map that receives generatedRelKeys from the probe cycle
// gets the placeholder "" entry created in the local mirror (m.contacts), not
// only in the persisted keystore — otherwise the next cycle, still finding an
// empty Devices in memory, would generate a NEW, different key pair every
// round, an infinite non-converging regeneration.
func TestProbeResultAppliesGeneratedRelKeysToEmptyDevices(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := model{
		contactStates: map[string]contactState{},
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
		}},
	}
	gk := &RelKeyUpdate{
		RelIdentityPriv: bytes.Repeat([]byte{0x01}, ed25519.PrivateKeySize),
		RelContentPriv:  bytes.Repeat([]byte{0x02}, ed25519.PrivateKeySize),
	}
	mm, _ := m.Update(probeResultMsg{results: []contactProbeResult{
		{netUsername: "bob", netPub: bobPub, username: "bob", online: true, generatedRelKeys: gk},
	}})
	m2 := mm.(model)
	dev, ok := m2.contacts[0].SoleDevice()
	if !ok {
		t.Fatal("Devices must contain the placeholder entry after the generated keys are applied")
	}
	if string(dev.RelIdentityPriv) != string(gk.RelIdentityPriv) || string(dev.RelContentPriv) != string(gk.RelContentPriv) {
		t.Error("the generated keys were not applied correctly to the local mirror")
	}

	// Next cycle, without generatedRelKeys (as probeContacts would do once
	// finding Devices no longer empty): the placeholder must remain
	// stable, neither disappearing nor being replaced.
	mm2, _ := m2.Update(probeResultMsg{results: []contactProbeResult{
		{netUsername: "bob", netPub: bobPub, username: "bob", online: true},
	}})
	m3 := mm2.(model)
	dev2, ok := m3.contacts[0].SoleDevice()
	if !ok || string(dev2.RelIdentityPriv) != string(gk.RelIdentityPriv) {
		t.Error("the placeholder entry must stay stable between one probe cycle and the next")
	}
}

// TestPickerItems covers the main branches of pickerItems() for contactPickerCmd:
// saved groups, pending invites, offline members to re-invite, contacts already
// members excluded from /grp-add-member, and the generic text filter.
// pickerKeyToUsername decodes a picker key generated by the "default" branch
// of pickerItems() (contactPickerKey, IdentityPub-based), resolving it back
// to the corresponding contact's username — used by the tests below to
// keep readable assertions even though the key is not the username,
// which would be ambiguous between contacts sharing the same name.
func pickerKeyToUsername(m model, key string) string {
	pub, ok := decodePickerContactKey(key)
	if !ok {
		return key
	}
	if c := m.resolveContactByPub(pub); c != nil {
		return c.Username
	}
	return ""
}

func TestPickerItems(t *testing.T) {
	contacts := []ContactInfo{
		{Username: "bob", LocalName: "Bobby", IdentityPub: bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize)},
		{Username: "carol", Verified: true, IdentityPub: bytes.Repeat([]byte{0x02}, ed25519.PublicKeySize)},
		{Username: "dave", IdentityPub: bytes.Repeat([]byte{0x03}, ed25519.PublicKeySize)},
	}

	t.Run("client.CmdRecall lists saved groups filtered by name", func(t *testing.T) {
		m := model{
			contactPickerCmd: client.CmdRecall,
			savedGroups: []GroupInfo{
				{LocalName: "Team", GroupID: "aaaa"},
				{GroupID: "bbbb"},
			},
		}
		items := m.pickerItems()
		if len(items) != 2 {
			t.Fatalf("expected 2 saved groups, got %d (%v)", len(items), items)
		}
		m.contactPickerFilter = "team"
		items = m.pickerItems()
		if len(items) != 1 || items[0] != "Team" {
			t.Fatalf("expected filter to keep only 'Team', got %v", items)
		}
	})

	t.Run("client.CmdJoin lists pending group knocks", func(t *testing.T) {
		m := model{
			contactPickerCmd: client.CmdJoin,
			pendingKnocks: []pendingKnock{
				{KnockPayload: shared.KnockPayload{GroupID: "g1", FromUsername: "bob"}},
				{KnockPayload: shared.KnockPayload{FromUsername: "no-group"}}, // empty GroupID, discarded
			},
		}
		items := m.pickerItems()
		if len(items) != 1 || items[0] != "g1" {
			t.Fatalf("expected only the pending group invite, got %v", items)
		}
	})

	t.Run("client.CmdReinvite lists only offline group members", func(t *testing.T) {
		tab := &roomTab{
			online:       []string{testKey("bob")}, // bob is connected now
			groupMembers: []GroupMember{{Username: "alice", IdentityPub: testPub("alice")}, {Username: "bob", IdentityPub: testPub("bob")}, {Username: "carol", IdentityPub: testPub("carol")}},
		}
		tab.setGroupLabels()
		m := model{
			contactPickerCmd: client.CmdReinvite,
			active:           0,
			tabs:             []*roomTab{tab},
			myUsername:       "alice",
			myIdentityPub:    testPub("alice"),
		}
		items := m.pickerItems()
		if len(items) != 1 || items[0] != memberPickerKey(tab.groupMembers[2]) {
			t.Fatalf("expected only carol (offline, not self), got %v", items)
		}
	})

	t.Run("client.CmdAddMember excludes contacts already in the current group", func(t *testing.T) {
		m := model{
			contactPickerCmd: client.CmdAddMember,
			active:           0,
			tabs: []*roomTab{{
				groupMembers: []GroupMember{{Username: "alice", IdentityPub: testPub("alice")}, {Username: "bob", IdentityPub: contacts[0].IdentityPub}},
			}},
			contacts: contacts,
		}
		items := m.pickerItems()
		for _, it := range items {
			if pickerKeyToUsername(m, it) == "bob" {
				t.Fatalf("bob is already a group member and should have been excluded, got %v", items)
			}
		}
		found := false
		for _, it := range items {
			if u := pickerKeyToUsername(m, it); u == "carol" || u == "dave" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected carol and/or dave to be offered, got %v", items)
		}
	})

	t.Run("client.CmdVerifySafety lists every contact, verified or not", func(t *testing.T) {
		m := model{contactPickerCmd: client.CmdVerifySafety, contacts: contacts}
		items := m.pickerItems()
		found := false
		for _, it := range items {
			if pickerKeyToUsername(m, it) == "carol" {
				found = true
			}
		}
		if !found {
			t.Fatalf("carol is already verified but must still appear in the picker, got %v", items)
		}
	})

	t.Run("client.CmdUnverifySafety lists only verified contacts", func(t *testing.T) {
		m := model{contactPickerCmd: client.CmdUnverifySafety, contacts: contacts}
		items := m.pickerItems()
		if len(items) == 0 {
			t.Fatal("expected at least one verified contact")
		}
		for _, it := range items {
			if c := m.resolveNameOrPickerKey(it); c == nil || !c.Verified {
				t.Fatalf("unverified contact offered: %q (%v)", pickerKeyToUsername(m, it), items)
			}
		}
	})

	t.Run("default branch filters contacts by display name", func(t *testing.T) {
		m := model{contactPickerCmd: client.CmdEdit, contacts: contacts, contactPickerFilter: "bob"}
		items := m.pickerItems()
		if len(items) != 1 || pickerKeyToUsername(m, items[0]) != "bob" {
			t.Fatalf("expected only bob to match the filter, got %v", items)
		}
	})
}

// TestCmdJoin covers the same ratchet DH ↔ SenderKey invariant as TestCmdInvite but
// from the side of whoever ACCEPTS an invite (/grp-join): the decision is recomputed
// independently from the member count of the received knock, and must match the
// one made by the host in cmdInvite/cmdAddMember. The returned tea.Cmd runs
// ConnectWithRetry over the network if invoked: only the synchronous state is
// verified here (tab created, pendingKnocks updated), never the cmd itself.
func TestCmdJoin(t *testing.T) {
	newModel := func(members []shared.MemberInfo) *model {
		return &model{
			myUsername: "alice",
			contacts: []ContactInfo{
				{
					Username:    "bob",
					IdentityPub: testPub("bob"),
					Devices: map[string]*keystore.DeviceRelation{
						"d": {
							RelIdentityPriv:    make([]byte, ed25519.PrivateKeySize),
							PeerRelIdentityPub: make([]byte, ed25519.PublicKeySize),
						},
					},
				},
			},
			pendingKnocks: []pendingKnock{
				{KnockPayload: shared.KnockPayload{
					GroupID:         "g1",
					FromUsername:    "bob",
					FromIdentityPub: testPub("bob"), // must match contact.IdentityPub above — resolveContactByPub, never by name
					FromAddr:        "bobonion.onion",
					RoomSecret:      []byte("secret"),
					Members:         members,
				}},
			},
		}
	}

	t.Run("opens the picker for an unknown group invite instead of erroring", func(t *testing.T) {
		m := newModel(nil)
		if cmd := m.cmdJoin("does-not-exist"); cmd != nil {
			t.Fatalf("expected nil tea.Cmd (picker opened), got a command")
		}
		if !m.contactPickerMode || m.contactPickerCmd != client.CmdJoin || m.contactPickerFilter != "does-not-exist" {
			t.Errorf("expected picker open for client.CmdJoin filtered on %q, got mode=%v cmd=%v filter=%q",
				"does-not-exist", m.contactPickerMode, m.contactPickerCmd, m.contactPickerFilter)
		}
		if len(m.tabs) != 0 {
			t.Errorf("expected no tab to be created, got %d", len(m.tabs))
		}
	})

	t.Run("accepting a 2-member invite creates a ratchet DH room", func(t *testing.T) {
		m := newModel([]shared.MemberInfo{{Username: "bob"}, {Username: "alice"}})
		if cmd := m.cmdJoin("g1"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		if len(m.tabs) != 1 {
			t.Fatalf("expected 1 tab, got %d", len(m.tabs))
		}
		tab := m.tabs[0]
		if !tab.cli.RatchetDH() {
			t.Error("expected ratchet DH to be active for a 2-member invite")
		}
		if tab.hostKey != testKey("bob") {
			t.Errorf("expected hostKey of bob, got %q", tab.hostKey)
		}
		if len(m.pendingKnocks) != 0 {
			t.Errorf("expected the accepted knock to be removed from pendingKnocks, got %d remaining", len(m.pendingKnocks))
		}
	})

	t.Run("accepting a 3+-member invite creates a SenderKey group", func(t *testing.T) {
		m := newModel([]shared.MemberInfo{{Username: "bob"}, {Username: "alice"}, {Username: "carol"}})
		if cmd := m.cmdJoin("g1"); cmd == nil {
			t.Fatal("expected a non-nil tea.Cmd")
		}
		tab := m.tabs[0]
		if tab.cli.RatchetDH() {
			t.Error("expected no ratchet DH for a 3-member invite")
		}
		if len(tab.groupMembers) != 3 {
			t.Errorf("expected 3 group members, got %d", len(tab.groupMembers))
		}
	})
}

// TestCmdReconnectTriggersRekeyOnNextInit covers the rekey folded into
// /grp-reconnect: cmdReconnect sets rekeyOnNextInit, and the next "init" frame
// consumes it, triggering RotateSenderKey — once only, not on every init.
// TestCmdMsgSetsPendingReplyToOnlyForShownMessage covers the explicit-reply
// constraint: /msg N is accepted only if N corresponds to a line already shown
// in the active tab (chatLine.gseq), otherwise rejected without touching
// pendingReplyTo.
func TestCmdMsgSetsPendingReplyToOnlyForShownMessage(t *testing.T) {
	tab := &roomTab{name: "room1", lines: []chatLine{{username: "bob", text: "hello", gseq: 27}}}
	m := &model{tabs: []*roomTab{tab}, active: 0, consoleIdx: 0}

	if cmd := m.cmdMsg("99"); cmd == nil {
		t.Fatal("want an error command for a number not shown")
	}
	if tab.pendingReplyTo != 0 {
		t.Errorf("pendingReplyTo must not change for a number not found, got %d", tab.pendingReplyTo)
	}

	if cmd := m.cmdMsg("27"); cmd != nil {
		t.Error("want nil (no error) for a number actually shown")
	}
	if tab.pendingReplyTo != 27 {
		t.Errorf("pendingReplyTo: want 27, got %d", tab.pendingReplyTo)
	}
}

// TestReplySentMsgResetsPendingReplyTo covers the one-shot behavior: the
// reply target is cleared ONLY when replySentMsg arrives (successful send),
// never on a blocked or failed attempt (which never generates this
// message, see sendMessage).
func TestReplySentMsgResetsPendingReplyTo(t *testing.T) {
	tab := &roomTab{name: "room1", pendingReplyTo: 27}
	m := &model{tabs: []*roomTab{tab}, active: 0, ready: true}

	m.Update(replySentMsg{tabIdx: 0})
	if tab.pendingReplyTo != 0 {
		t.Errorf("pendingReplyTo: want 0 after replySentMsg, got %d", tab.pendingReplyTo)
	}
}

func TestCmdReconnectTriggersRekeyOnNextInit(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.Conn = newTestWSConn(t)

	tab := &roomTab{name: "room1", cli: cli, ctx: context.Background()}
	m := &model{tabs: []*roomTab{tab}, active: 0}

	if tab.rekeyOnNextInit {
		t.Fatal("rekeyOnNextInit must not start true")
	}

	m.cmdReconnect()
	if !tab.rekeyOnNextInit {
		t.Fatal("cmdReconnect must set rekeyOnNextInit")
	}

	keyIDBefore := cli.SenderKeyIDForTest()
	initFrame := map[string]any{
		"type": "init",
		"users": []any{
			map[string]any{"user_id": "u1", "username": "peer"},
		},
	}

	cmds := m.handleRoomMsg(0, initFrame)
	if tab.rekeyOnNextInit {
		t.Error("rekeyOnNextInit must be consumed (back to false) after the init")
	}
	for _, cmd := range cmds {
		if cmd != nil {
			cmd()
		}
	}
	if cli.SenderKeyIDForTest() == keyIDBefore {
		t.Error("want a new senderKeyID after the rotation triggered by the init")
	}

	// A second init in the same session must not re-trigger the rotation.
	keyIDAfterFirst := cli.SenderKeyIDForTest()
	cmds = m.handleRoomMsg(0, initFrame)
	for _, cmd := range cmds {
		if cmd != nil {
			cmd()
		}
	}
	if cli.SenderKeyIDForTest() != keyIDAfterFirst {
		t.Error("a second init must not trigger a second rotation")
	}
}

// TestRoomKeepsHomonymMembersApart: two members invited under the same
// username but with different identity keys are two distinct members of
// the room — both online, both named distinctly, and the departure of
// one never marks the other offline.
func TestRoomKeepsHomonymMembersApart(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	tab := &roomTab{cli: cli, groupID: "g1", groupMembers: []GroupMember{
		{Username: "me", IdentityPub: testPub("me")},
		{Username: "bob", IdentityPub: testPub("bob-1")},
		{Username: "bob", IdentityPub: testPub("bob-2")},
	}}
	tab.setGroupLabels()
	m := &model{tabs: []*roomTab{tab}, active: 0, myUsername: "me", myIdentityPub: testPub("me")}

	entry := func(uid, name, who string) map[string]any {
		return map[string]any{"user_id": uid, "username": name, "identity_pub": base64.StdEncoding.EncodeToString(testPub(who))}
	}
	m.handleRoomMsg(0, map[string]any{"type": "init", "users": []any{entry("u-me", "me", "me"), entry("u-b1", "bob", "bob-1")}})
	joined := entry("u-b2", "bob", "bob-2")
	joined["type"] = "user_joined"
	m.handleRoomMsg(0, joined)

	if !tab.isOnline(testKey("bob-1")) || !tab.isOnline(testKey("bob-2")) {
		t.Fatalf("both bobs must be online, online=%v", tab.online)
	}
	if cli.LookupUserID(testKey("bob-1")) != "u-b1" || cli.LookupUserID(testKey("bob-2")) != "u-b2" {
		t.Fatal("each bob must keep its own session userID")
	}
	if a, b := m.memberName(tab, testKey("bob-1")), m.memberName(tab, testKey("bob-2")); a == b {
		t.Errorf("homonyms shown with the same name %q", a)
	}

	m.handleRoomMsg(0, map[string]any{"type": "user_left", "user_id": "u-b1", "reason": "left"})
	if tab.isOnline(testKey("bob-1")) {
		t.Error("the bob who left must be offline")
	}
	if !tab.isOnline(testKey("bob-2")) {
		t.Error("the other bob must still be online")
	}
	if tab.departures[testKey("bob-2")] != memberCrashed || tab.departures[testKey("bob-1")] != memberLeft {
		t.Errorf("departures = %v, want only the first bob as left", tab.departures)
	}
}

// TestParseMsgIDPreservesFullPrecision verifies that msg_id survives a full
// JSON.Marshal→Unmarshal round trip at full uint64 precision: msg_id is a
// random uint64 (Client.Send, crypto/rand) read back via map[string]any — as
// Client.ReadMsg does for every frame — where a JSON number always decodes
// as float64, exact only up to 2^53. msg_id is encoded as a decimal string
// on the wire specifically to avoid this precision loss.
func TestParseMsgIDPreservesFullPrecision(t *testing.T) {
	for i := 0; i < 20; i++ {
		var buf [8]byte
		_, _ = rand.Read(buf[:])
		orig := binary.BigEndian.Uint64(buf[:])

		raw, err := json.Marshal(map[string]any{"msg_id": strconv.FormatUint(orig, 10)})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}

		if got := parseMsgID(decoded["msg_id"]); got != orig {
			t.Errorf("msgID=%d: round-trip ha dato %d", orig, got)
		}
	}
}

// TestParseMessageUsesSelfEchoCache verifies that with ratchetDH active,
// decrypting the self-echo of our own message bypasses the generic ratchet
// path entirely (the published dhr identifies a PEER key, never our own —
// looking it up in our own outEphRing never finds it) and instead reuses the
// text already known from having written it ourselves. The keyID below is
// deliberately nonexistent: if the bypass did not trigger, DecryptMsg would
// fail for certain ("sender key unavailable"). msgID is deliberately > 2^53
// (full width, as Send() actually generates): a small value like 12345 would
// survive even the float64 precision issue (map[string]any decodes JSON
// numbers as float64, exact only up to 2^53) without ever exposing it — see
// the comment on wsIncoming.MsgID in internal/server/ws.go.
func TestParseMessageUsesSelfEchoCache(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	const msgID = uint64(15850307506488844170)
	cli.SeedSentTextForTest(msgID, "hello")

	tab := &roomTab{cli: cli}
	m := &model{myUsername: "me", tabs: []*roomTab{tab}, active: 0}

	frame := map[string]any{
		"kid":          "keyid-nonexistent",
		"text":         "undecryptable",
		"idx":          float64(0),
		"msg_id":       strconv.FormatUint(msgID, 10),
		"from_user_id": "u1",
	}

	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine from the cached self-echo")
	}
	if line.text != "hello" {
		t.Errorf("want text from the cache %q, got %q", "hello", line.text)
	}
	if line.username != "me" {
		t.Errorf("want username 'me' (self-echo), got %q", line.username)
	}
	if _, _, ok := cli.TakeSentText(msgID); ok {
		t.Error("the msgID should have been consumed by parseMessage, no longer available")
	}
}

// buildDeviceSignedFrame builds an incoming message frame (kid/text/
// idx/device_sig/device_ts) encrypted for keyID with chain0, whose sealedMsg
// carries DP=devicePub — helper shared by the device-tag tests below.
func buildDeviceSignedFrame(t *testing.T, chain0 []byte, devicePub ed25519.PublicKey, signWith ed25519.PrivateKey, from, text string) map[string]any {
	t.Helper()
	enc, err := client.EncryptTestSealedFrame(chain0, 0, from, text, devicePub)
	if err != nil {
		t.Fatalf("EncryptTestSealedFrame: %v", err)
	}
	ts := "2026-08-10T12:00:00Z"
	sig := shared.SignDeviceSig(signWith, enc, ts)
	return map[string]any{
		"kid":          "keyid-device-tag",
		"text":         enc,
		"idx":          float64(0),
		"device_sig":   base64.StdEncoding.EncodeToString(sig),
		"device_ts":    ts,
		"from_user_id": "uid-" + from,
	}
}

// TestParseMessageDeviceTagTOFUAdopt covers the first TOFU adoption of a
// contact's device pubkey: no prior KnownDevicePub, the signature verifies →
// tag "DEV:xxxxxxxx" (not "new"), and ContactInfo.KnownDevicePub gets
// populated for next time.
func TestParseMessageDeviceTagTOFUAdopt(t *testing.T) {
	senderKey := make([]byte, 32)
	rand.Read(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-device-tag"

	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)

	cli.RegisterUser("uid-alice", "alice", testPub("alice"))
	tab := &roomTab{cli: cli}
	var savedContact []byte
	var savedPub []byte
	m := &model{
		myUsername: "me",
		tabs:       []*roomTab{tab},
		active:     0,
		contacts:   []ContactInfo{{Username: "alice", IdentityPub: testPub("alice")}},
		onContactDevicePub: func(contactPub []byte, pub []byte) error {
			savedContact, savedPub = contactPub, pub
			return nil
		},
	}

	frame := buildDeviceSignedFrame(t, chain0, devicePub, devicePriv, "alice", "hello")
	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine")
	}
	wantTag := "DEV:" + hex.EncodeToString(devicePub)[len(hex.EncodeToString(devicePub))-8:]
	if line.deviceTag != wantTag {
		t.Errorf("deviceTag = %q, want %q", line.deviceTag, wantTag)
	}
	if line.deviceTagNew {
		t.Error("the first TOFU adoption must not be marked as 'new device'")
	}
	if !bytes.Equal(m.contacts[0].KnownDevicePub, devicePub) {
		t.Error("KnownDevicePub not updated after the first TOFU adoption")
	}
	if !bytes.Equal(savedContact, testPub("alice")) || !bytes.Equal(savedPub, devicePub) {
		t.Errorf("onContactDevicePub not called correctly: contact=%x pub=%x", savedContact, savedPub)
	}
}

// TestParseMessageDeviceTagChanged covers the "device different from the
// already known one" case: never a message rejection, only a distinct tag
// ("new") and a non-blocking update of KnownDevicePub to the newly seen device.
func TestParseMessageDeviceTagChanged(t *testing.T) {
	senderKey := make([]byte, 32)
	rand.Read(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-device-tag"

	oldDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	newDevicePub, newDevicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)

	cli.RegisterUser("uid-alice", "alice", testPub("alice"))
	tab := &roomTab{cli: cli}
	m := &model{
		myUsername: "me",
		tabs:       []*roomTab{tab},
		active:     0,
		contacts:   []ContactInfo{{Username: "alice", IdentityPub: testPub("alice"), KnownDevicePub: oldDevicePub}},
	}

	frame := buildDeviceSignedFrame(t, chain0, newDevicePub, newDevicePriv, "alice", "hello")
	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine")
	}
	if !line.deviceTagNew {
		t.Error("a device different from the known one must produce the 'new' tag")
	}
	if !bytes.Equal(m.contacts[0].KnownDevicePub, newDevicePub) {
		t.Error("KnownDevicePub must update on a different device too (non-blocking)")
	}
	if line.text != "hello" {
		t.Error("a different device must never prevent decrypting/showing the message")
	}
}

// TestParseMessageDeviceTagInvalidSigShowsNoTag covers the remaining design
// case: a device_sig that fails to verify at all against the just-decrypted
// DP must never produce a tag (nor block the message) — unlike the content
// signature, which instead shows an explicit "[invalid signature]" tag.
func TestParseMessageDeviceTagInvalidSigShowsNoTag(t *testing.T) {
	senderKey := make([]byte, 32)
	rand.Read(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-device-tag"

	devicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader) // signs with a key different from devicePub
	if err != nil {
		t.Fatal(err)
	}

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)

	tab := &roomTab{cli: cli}
	m := &model{
		myUsername: "me",
		tabs:       []*roomTab{tab},
		active:     0,
		contacts:   []ContactInfo{{Username: "alice"}},
	}

	frame := buildDeviceSignedFrame(t, chain0, devicePub, wrongPriv, "alice", "hello")
	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine")
	}
	if line.deviceTag != "" {
		t.Errorf("invalid device_sig: want no tag, got %q", line.deviceTag)
	}
	if len(m.contacts[0].KnownDevicePub) != 0 {
		t.Error("invalid device_sig: KnownDevicePub must not be updated")
	}
	if line.text != "hello" {
		t.Error("an invalid device_sig must never prevent decrypting/showing the message")
	}
}

// TestSendCachesTextForSelfEcho covers the Send()→TakeSentText round trip at
// the Client level: the text is cached only on a successful send, and is
// consumed exactly once.
func TestSendCachesTextForSelfEcho(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, true, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.Conn = newTestWSConn(t)

	msgID, err := cli.Send(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	text, _, ok := cli.TakeSentText(msgID)
	if !ok || text != "hello" {
		t.Fatalf("want cached text %q, ok=true; got %q, ok=%v", "hello", text, ok)
	}
	if _, _, ok := cli.TakeSentText(msgID); ok {
		t.Error("TakeSentText must consume the entry: a second call must not find it")
	}
}

// TestInvitePickerFilter covers the search in the /grp-invite picker:
// typing filters by local name or username, Space stays dedicated to the
// selection toggle (it never enters the filter text, unlike the
// single-selection picker /cnt-info-/cnt-edit where Space has nothing else to
// do), and an existing selection survives the filter changing because
// inviteSelected is indexed by username, not by list position.
func TestInvitePickerFilter(t *testing.T) {
	m := &model{
		tabs:   []*roomTab{},
		active: 0,
		contacts: []ContactInfo{
			{Username: "bob123", LocalName: "Bob"},
			{Username: "carol456", LocalName: "Carol"},
			{Username: "dave789"},
		},
		invitePickerMode: true,
		inviteCandidates: []string{"bob123", "carol456", "dave789"},
		inviteSelected:   make(map[string]bool),
	}

	press := func(msg tea.KeyMsg) {
		mm, _ := m.Update(msg)
		*m = mm.(model)
	}

	// Typing "bob" filters down to a single entry (by local name, not literal username).
	press(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("bob")})
	items := m.inviteFilteredCandidates()
	if len(items) != 1 || items[0] != "bob123" {
		t.Fatalf("want only 'bob123' with filter 'bob', got %v", items)
	}

	// Space selects the highlighted (filtered) entry, it never ends up in the filter text.
	press(tea.KeyMsg{Type: tea.KeySpace})
	if m.inviteFilter != "bob" {
		t.Errorf("the filter must not change on Space, got %q", m.inviteFilter)
	}
	if !m.inviteSelected["bob123"] {
		t.Error("want 'bob123' selected after Space")
	}

	// Backspace removes the last filter character, widening the results again —
	// the existing selection on bob123 must survive (indexed by username).
	press(tea.KeyMsg{Type: tea.KeyBackspace})
	press(tea.KeyMsg{Type: tea.KeyBackspace})
	press(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.inviteFilter != "" {
		t.Errorf("want an empty filter after 3 backspaces on 'bob', got %q", m.inviteFilter)
	}
	items = m.inviteFilteredCandidates()
	if len(items) != 3 {
		t.Fatalf("want all 3 contacts with the empty filter, got %v", items)
	}
	if !m.inviteSelected["bob123"] {
		t.Error("the bob123 selection must not disappear when the filter widens")
	}
}

// TestFileChunkAckRoutedViaSendingRegistry verifies that "file_chunk_ack"
// looks up the transfer in outgoingTransfersSending, not in outgoingTransfers:
// the latter is cleared the instant the real send starts (the three call
// sites of startSendingChunks), so an ack lookup against it would never reach
// the sending goroutine once sending has begun. Here the transfer is
// registered ONLY in outgoingTransfersSending, matching what
// startSendingChunks actually does.
func TestFileChunkAckRoutedViaSendingRegistry(t *testing.T) {
	ft := &outgoingFileTransfer{
		transferID: "t1",
		ackCh:      make(chan fileChunkAckEvent, 4),
	}
	m := &model{
		tabs:                     []*roomTab{{cli: client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})}},
		outgoingTransfersSending: map[string]*outgoingFileTransfer{"t1": ft},
	}

	m.handleRoomMsg(0, map[string]any{
		"type":         "file_chunk_ack",
		"from_user_id": "peer1",
		"transfer_id":  "t1",
		"seq":          float64(3),
	})

	select {
	case ev := <-ft.ackCh:
		if ev.seq != 3 || ev.fromUserID != "peer1" {
			t.Errorf("want {seq:3 fromUserID:peer1}, got %+v", ev)
		}
	default:
		t.Fatal("the ack didn't arrive on ft.ackCh — the lookup didn't find the transfer")
	}
}

// newRecordingWSConn starts a test WS server that decodes every incoming
// frame into map[string]any and queues a copy on recorded — used to verify
// EXACTLY which frames a Client writes (to_user_ids, seq, payload) without
// simulating multiple real connections: a single Client/single WS connection
// still writes one frame per logical recipient, distinguishable by the
// to_user_ids field.
func newRecordingWSConn(t *testing.T) (*websocket.Conn, <-chan map[string]any) {
	t.Helper()
	recorded := make(chan map[string]any, 256)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		for {
			var v map[string]any
			if err := wsjson.Read(r.Context(), conn, &v); err != nil {
				return
			}
			recorded <- v
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn, recorded
}

// TestStartSendingChunksResumeCatchUp covers a real resume: a recipient
// (userB) joins mid-transfer via resumeCh with fromByte=0 (has nothing yet) —
// it must receive both the chunks already sent to userA (catch-up, same
// bytes, new seqs) and every subsequent chunk through completion, exactly
// like userA. An auto-acker consumes every recorded frame and immediately
// acks for each recipient listed in to_user_ids — avoiding manual
// synchronization with the exact interleaving of the sending goroutine.
func TestStartSendingChunksResumeCatchUp(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, recorded := newRecordingWSConn(t)
	cli.Conn = conn

	const chunkSize = 1024
	const numChunks = 5
	ciphertext := make([]byte, numChunks*chunkSize)
	for i := range ciphertext {
		ciphertext[i] = byte(i / chunkSize) // each chunk filled with its own index: 0,1,2,3,4
	}

	tab := &roomTab{cli: cli, ctx: context.Background()}
	m := model{
		tabs:                         []*roomTab{tab},
		fileWarpChunkSizeKiB:         1, // 1024 bytes/chunk
		fileWarpMaxInFlightChunks:    2,
		fileTransferReconnectTimeout: 5 * time.Second,
	}
	ft := &outgoingFileTransfer{
		transferID: "resume-test",
		tabIdx:     0,
		fileName:   "test.bin",
		ciphertext: ciphertext,
		preset:     "warp",
		accepted:   []string{"userA"},
	}

	cmd := m.startSendingChunks(ft)
	if ft.ackCh == nil || ft.resumeCh == nil {
		t.Fatal("ackCh/resumeCh not set by startSendingChunks")
	}

	var mu sync.Mutex
	seenByUser := make(map[string]map[int]bool) // username → chunk index (payload[0]) seen

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case frame := <-recorded:
				toUsers, _ := frame["to_user_ids"].([]any)
				seqF, _ := frame["seq"].(float64)
				payloadB64, _ := frame["payload"].(string)
				payload, _ := base64.StdEncoding.DecodeString(payloadB64)
				chunkIdx := -1
				if len(payload) > 0 {
					chunkIdx = int(payload[0])
				}
				mu.Lock()
				for _, u := range toUsers {
					uname, _ := u.(string)
					if seenByUser[uname] == nil {
						seenByUser[uname] = make(map[int]bool)
					}
					seenByUser[uname][chunkIdx] = true
				}
				mu.Unlock()
				// Deliberate delay: without it, with a single recipient (userA) and
				// window=2, the entire 5-chunk transfer would finish in microseconds, before
				// the test can even get the resume event for userB through.
				time.Sleep(15 * time.Millisecond)
				for _, u := range toUsers {
					uname, _ := u.(string)
					select {
					case ft.ackCh <- fileChunkAckEvent{seq: uint64(seqF), fromUserID: uname}:
					default:
					}
				}
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)

	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()

	// Wait for the transfer to have actually started for userA before letting
	// userB join — a weak condition (just 1 chunk), robust against the
	// goroutine scheduling order.
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		started := len(seenByUser["userA"]) > 0
		mu.Unlock()
		if started {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for the first chunk for userA")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// isNewAccept: true — simulates the "re-admitted" fallback (case "file_accept"
	// in Update()) for a genuine first acceptance arriving after sending had
	// already started toward userA, not a bare file_resume: a file_resume from a
	// recipient that was never accepted is ignored — see
	// fileResumeEvent.isNewAccept.
	ft.resumeCh <- fileResumeEvent{memberKey: "userB", toUserID: "userB", fromByte: 0, isNewAccept: true}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: startSendingChunks didn't complete the transfer")
	}

	mu.Lock()
	defer mu.Unlock()
	for idx := 0; idx < numChunks; idx++ {
		if !seenByUser["userA"][idx] {
			t.Errorf("userA: chunk %d missing", idx)
		}
		if !seenByUser["userB"][idx] {
			t.Errorf("userB: chunk %d missing (recovery/resume didn't work)", idx)
		}
	}
}

// ── remote_nuke ─────────────────────────────────────────────────────────

// newRemoteNukeTestModel builds a minimal model with myDeviceID and
// authorityPubKeys set (receiving-side verification) — dialTor left nil:
// executeRemoteNuke skips both network phases and returns
// remoteNukeExecutedMsg right away, allowing handleRemoteNuke to be tested
// synchronously without real I/O.
func newRemoteNukeTestModel(myDeviceID []byte, authorityPubKeys []ed25519.PublicKey) *model {
	return &model{
		tabs:              []*roomTab{{isConsole: true}},
		consoleIdx:        0,
		myDeviceID:        myDeviceID,
		authorityPubKeys:  authorityPubKeys,
		remoteNukeCancels: make(map[string]*remoteNukeEntry),
		remoteNukeMu:      &sync.Mutex{},
	}
}

// signedRemoteNukeAck generates a device-level key pair and signs a genuine
// ack for targetDeviceID — used by tests that need to pass
// handleRemoteNukeAck's verification. The caller must still populate
// the known devices with the returned entry, otherwise the signature would
// verify correctly but the lookup by TargetDeviceID would fail.
func signedRemoteNukeAck(targetDeviceID []byte) (shared.KnockPayload, DeviceRecordInfo) {
	devicePub, devicePriv, _ := ed25519.GenerateKey(rand.Reader)
	ts := shared.NowTS()
	sig := shared.SignRemoteNukeAck(devicePriv, targetDeviceID, ts)
	return shared.KnockPayload{
			Type:           "remote_nuke_ack",
			FromUsername:   "target-device",
			TargetDeviceID: targetDeviceID,
			NukeTs:         ts,
			NukeSig:        sig,
		}, DeviceRecordInfo{
			DeviceID:  targetDeviceID,
			DevicePub: devicePub,
		}
}

func TestHandleRemoteNukeAcceptsValidCommand(t *testing.T) {
	authorityPub, authorityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := shared.NowTS()
	sig := shared.SignRemoteNuke(authorityPriv, targetDeviceID, ts)

	m := newRemoteNukeTestModel(targetDeviceID, []ed25519.PublicKey{authorityPub})
	cmd := m.handleRemoteNuke(shared.KnockPayload{
		Type:           "remote_nuke",
		FromUsername:   "authority",
		TargetDeviceID: targetDeviceID,
		NukeTs:         ts,
		NukeSig:        sig,
	})
	if cmd == nil {
		t.Fatal("want a tea.Cmd for a valid remote_nuke command")
	}
	msg := cmd()
	if _, ok := msg.(remoteNukeExecutedMsg); !ok {
		t.Fatalf("want remoteNukeExecutedMsg, got %T", msg)
	}
}

func TestHandleRemoteNukeRejectsWrongTarget(t *testing.T) {
	authorityPub, authorityPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	otherDeviceID := make([]byte, 16)
	rand.Read(otherDeviceID)
	ts := shared.NowTS()
	sig := shared.SignRemoteNuke(authorityPriv, targetDeviceID, ts)

	// myDeviceID is otherDeviceID: the command is for a different device.
	m := newRemoteNukeTestModel(otherDeviceID, []ed25519.PublicKey{authorityPub})
	cmd := m.handleRemoteNuke(shared.KnockPayload{
		Type:           "remote_nuke",
		TargetDeviceID: targetDeviceID,
		NukeTs:         ts,
		NukeSig:        sig,
	})
	if cmd != nil {
		t.Fatal("a remote_nuke command for another device must have no effect")
	}
}

func TestHandleRemoteNukeRejectsUnauthorizedSignature(t *testing.T) {
	_, unrelatedPriv, _ := ed25519.GenerateKey(rand.Reader)
	authorityPub, _, _ := ed25519.GenerateKey(rand.Reader) // never used to sign
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := shared.NowTS()
	sig := shared.SignRemoteNuke(unrelatedPriv, targetDeviceID, ts) // signed by a key NOT in authorityPubKeys

	m := newRemoteNukeTestModel(targetDeviceID, []ed25519.PublicKey{authorityPub})
	cmd := m.handleRemoteNuke(shared.KnockPayload{
		Type:           "remote_nuke",
		TargetDeviceID: targetDeviceID,
		NukeTs:         ts,
		NukeSig:        sig,
	})
	if cmd != nil {
		t.Fatal("a remote_nuke command signed by an unauthorized key must have no effect")
	}
}

func TestHandleRemoteNukeRejectsStaleTimestamp(t *testing.T) {
	authorityPub, authorityPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	staleTs := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	sig := shared.SignRemoteNuke(authorityPriv, targetDeviceID, staleTs)

	m := newRemoteNukeTestModel(targetDeviceID, []ed25519.PublicKey{authorityPub})
	cmd := m.handleRemoteNuke(shared.KnockPayload{
		Type:           "remote_nuke",
		TargetDeviceID: targetDeviceID,
		NukeTs:         staleTs,
		NukeSig:        sig,
	})
	if cmd != nil {
		t.Fatal("a remote_nuke command with an expired timestamp (replay) must have no effect")
	}
}

// TestHandleRemoteNukeAcceptsOldIdentityDuringRotation covers the case
// explicit in the design: the signature also verifies against an OLD
// identity key, not only the current one — necessary because
// authorityPubKeys always includes both during an ongoing rotation
// (see Keystore.AllAuthorityPubKeys).
func TestHandleRemoteNukeAcceptsOldIdentityKey(t *testing.T) {
	currentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := shared.NowTS()
	sig := shared.SignRemoteNuke(oldPriv, targetDeviceID, ts)

	m := newRemoteNukeTestModel(targetDeviceID, []ed25519.PublicKey{currentPub, oldPub})
	cmd := m.handleRemoteNuke(shared.KnockPayload{
		Type:           "remote_nuke",
		TargetDeviceID: targetDeviceID,
		NukeTs:         ts,
		NukeSig:        sig,
	})
	if cmd == nil {
		t.Fatal("a valid signature with the old identity key (rotation in progress) must be accepted")
	}
}

// TestHandleRemoteNukeAckCancelsFanOut covers stopping at the first ack: an
// incoming remote_nuke_ack must cancel the shared context of the still
// ongoing fan-out for the same DeviceID, and remove it from the map
// (no leak, no double cancellation later).
func TestHandleRemoteNukeAckCancelsFanOut(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	key := hex.EncodeToString(targetDeviceID)

	ctx, cancel := context.WithCancel(context.Background())
	m := newRemoteNukeTestModel(nil, nil)
	m.remoteNukeCancels[key] = &remoteNukeEntry{cancel: cancel}
	ack, rec := signedRemoteNukeAck(targetDeviceID)
	m.knownDevices = func() []DeviceRecordInfo { return []DeviceRecordInfo{rec} }

	cmd := m.handleRemoteNukeAck(ack)
	_ = cmd

	select {
	case <-ctx.Done():
	default:
		t.Fatal("handleRemoteNukeAck must cancel the running fan-out's context")
	}
	if _, ok := m.remoteNukeCancels[key]; ok {
		t.Error("handleRemoteNukeAck must remove the entry from the map after cancelling it")
	}
}

// TestHandleRemoteNukeAckForgedSignatureIgnored covers the other half of the
// ack verification: an ack with a non-genuine signature (or
// signed with a key that is not the one known for that TargetDeviceID) must
// have NO effect — no fan-out stop, no removal from the persistent queue —
// so the retry proceeds normally instead of blindly trusting an
// unauthenticated confirmation.
func TestHandleRemoteNukeAckForgedSignatureIgnored(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	key := hex.EncodeToString(targetDeviceID)

	// The known key for this device is one; the signature below is from a
	// different, on-the-fly generated pair (simulates a forged/inauthentic ack).
	knownPub, _, _ := ed25519.GenerateKey(rand.Reader)
	forgedAck, _ := signedRemoteNukeAck(targetDeviceID)

	ctx, cancel := context.WithCancel(context.Background())
	m := newRemoteNukeTestModel(nil, nil)
	m.remoteNukeCancels[key] = &remoteNukeEntry{cancel: cancel}
	m.knownDevices = func() []DeviceRecordInfo { return []DeviceRecordInfo{{DeviceID: targetDeviceID, DevicePub: knownPub}} }
	var cleared []byte
	m.clearPendingRemoteNuke = func(devID []byte) error {
		cleared = devID
		return nil
	}

	m.handleRemoteNukeAck(forgedAck)

	select {
	case <-ctx.Done():
		t.Fatal("an unauthenticated ack must not stop the running fan-out")
	default:
	}
	if _, ok := m.remoteNukeCancels[key]; !ok {
		t.Error("an unauthenticated ack must not remove the entry from the fan-out map")
	}
	if cleared != nil {
		t.Error("an unauthenticated ack must not empty the persistent queue")
	}
}

// TestHandleRemoteNukeAckStaleTsIgnored verifies the TsFresh check on
// remote_nuke_ack: an ack with a GENUINE signature but a ts outside the
// freshness window must have no effect — an old captured ack must not be
// able to stop the fan-out of a NEW remote_nuke command, nor make it look
// like the device was destroyed when it was not.
func TestHandleRemoteNukeAckStaleTsIgnored(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	key := hex.EncodeToString(targetDeviceID)

	devicePub, devicePriv, _ := ed25519.GenerateKey(rand.Reader)
	staleTs := "2020-01-01T00:00:00Z"
	sig := shared.SignRemoteNukeAck(devicePriv, targetDeviceID, staleTs)
	staleAck := shared.KnockPayload{
		Type:           "remote_nuke_ack",
		FromUsername:   "target-device",
		TargetDeviceID: targetDeviceID,
		NukeTs:         staleTs,
		NukeSig:        sig,
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := newRemoteNukeTestModel(nil, nil)
	m.remoteNukeCancels[key] = &remoteNukeEntry{cancel: cancel}
	m.knownDevices = func() []DeviceRecordInfo { return []DeviceRecordInfo{{DeviceID: targetDeviceID, DevicePub: devicePub}} }
	var cleared []byte
	m.clearPendingRemoteNuke = func(devID []byte) error {
		cleared = devID
		return nil
	}

	m.handleRemoteNukeAck(staleAck)

	select {
	case <-ctx.Done():
		t.Fatal("an ack with an expired ts (replay) must not stop the running fan-out, even with a genuine signature")
	default:
	}
	if _, ok := m.remoteNukeCancels[key]; !ok {
		t.Error("an ack with an expired ts must not remove the entry from the fan-out map")
	}
	if cleared != nil {
		t.Error("an ack with an expired ts must not empty the persistent queue")
	}
}

func TestHandleDangerBroadcastUnknownContactIgnored(t *testing.T) {
	unknownPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = nil // no known contact
	cmd := m.handleDangerBroadcast(shared.KnockPayload{
		Type:            "danger_broadcast",
		FromUsername:    "unknown",
		FromIdentityPub: unknownPub,
	})
	if cmd != nil {
		t.Error("a danger_broadcast from an unknown sender must produce no command")
	}
	if len(m.tabs[0].lines) != 0 {
		t.Error("a danger_broadcast from an unknown sender must write nothing to Console")
	}
}

func TestCmdRemoteNukeRegistersPendingStateAndDangerBroadcast(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	siblingPub, _, _ := ed25519.GenerateKey(rand.Reader)
	contactPub, _, _ := ed25519.GenerateKey(rand.Reader)

	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = []ContactInfo{{Username: "bob", IdentityPub: contactPub, NetAddr: "bob.onion"}}
	m.signRemoteNuke = func(devID []byte, ts string) []byte { return []byte("sig") }

	var addedTargetDeviceID []byte
	m.addPendingRemoteNuke = func(devID []byte) error {
		addedTargetDeviceID = devID
		return nil
	}
	var pendingPubs [][]byte
	m.setDangerBroadcastPending = func(devID []byte, pubs [][]byte) error {
		pendingPubs = pubs
		return nil
	}

	cmd := m.cmdRemoteNuke(DeviceRecordInfo{
		DeviceID: targetDeviceID,
		SiblingIdentities: []DeviceIdentityRef{
			{Username: "target", IdentityPub: siblingPub},
		},
	})
	if cmd == nil {
		t.Fatal("want a non-nil tea.Cmd from cmdRemoteNuke with valid targets")
	}
	if !bytes.Equal(addedTargetDeviceID, targetDeviceID) {
		t.Errorf("addPendingRemoteNuke called with the wrong targetDeviceID: %x", addedTargetDeviceID)
	}
	if len(pendingPubs) != 1 || !bytes.Equal(pendingPubs[0], contactPub) {
		t.Errorf("setDangerBroadcastPending called with unexpected keys: %x", pendingPubs)
	}
	if len(m.pendingDangerBroadcasts) != 1 || !bytes.Equal(m.pendingDangerBroadcasts[0].IdentityPubs[0], contactPub) {
		t.Errorf("in-memory pendingDangerBroadcasts not updated: %+v", m.pendingDangerBroadcasts)
	}
}

func TestHandleRemoteNukeAckClearsPendingQueue(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)

	m := newRemoteNukeTestModel(nil, nil)
	ack, rec := signedRemoteNukeAck(targetDeviceID)
	m.knownDevices = func() []DeviceRecordInfo { return []DeviceRecordInfo{rec} }
	var cleared []byte
	m.clearPendingRemoteNuke = func(devID []byte) error {
		cleared = devID
		return nil
	}

	m.handleRemoteNukeAck(ack)

	if !bytes.Equal(cleared, targetDeviceID) {
		t.Errorf("clearPendingRemoteNuke not called with the right targetDeviceID: %x", cleared)
	}
}

func TestHandleDangerBroadcastAckRemovesOnlyAckingUsername(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)

	m := newRemoteNukeTestModel(nil, nil)
	m.pendingDangerBroadcasts = []DangerBroadcastPendingInfo{
		{TargetDeviceID: targetDeviceID, IdentityPubs: [][]byte{testPub("bob"), testPub("carol")}},
	}
	var confirmedPub []byte
	m.confirmDangerBroadcast = func(devID, pub []byte) error {
		confirmedPub = pub
		return nil
	}

	m.handleDangerBroadcastAck(shared.KnockPayload{
		Type:            "danger_broadcast_ack",
		FromUsername:    "bob",
		FromIdentityPub: testPub("bob"),
		TargetDeviceID:  targetDeviceID,
	})

	if !bytes.Equal(confirmedPub, testPub("bob")) {
		t.Errorf("confirmDangerBroadcast not called with the right key, got %x", confirmedPub)
	}
	if len(m.pendingDangerBroadcasts) != 1 || len(m.pendingDangerBroadcasts[0].IdentityPubs) != 1 || !bytes.Equal(m.pendingDangerBroadcasts[0].IdentityPubs[0], testPub("carol")) {
		t.Fatalf("want only 'carol' left in the queue, found: %+v", m.pendingDangerBroadcasts)
	}
	if len(m.tabs[0].lines) != 1 {
		t.Errorf("want 1 Console line after a danger_broadcast_ack, found %d", len(m.tabs[0].lines))
	}
}

func TestHandleDangerBroadcastAckRemovesEntryWhenEmpty(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)

	m := newRemoteNukeTestModel(nil, nil)
	m.pendingDangerBroadcasts = []DangerBroadcastPendingInfo{
		{TargetDeviceID: targetDeviceID, IdentityPubs: [][]byte{testPub("bob")}},
	}

	m.handleDangerBroadcastAck(shared.KnockPayload{
		Type:            "danger_broadcast_ack",
		FromUsername:    "bob",
		FromIdentityPub: testPub("bob"),
		TargetDeviceID:  targetDeviceID,
	})

	if len(m.pendingDangerBroadcasts) != 0 {
		t.Fatalf("want 0 pending entries after the last ack, found %d", len(m.pendingDangerBroadcasts))
	}
}

func TestHandleDangerBroadcastKnownContactNotified(t *testing.T) {
	contactPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = []ContactInfo{{Username: "alice", IdentityPub: contactPub}}
	m.handleDangerBroadcast(shared.KnockPayload{
		Type:            "danger_broadcast",
		FromUsername:    "alice",
		FromIdentityPub: contactPub,
	})
	if len(m.tabs[0].lines) != 1 {
		t.Fatalf("want 1 Console line after a danger_broadcast from a known contact, found %d", len(m.tabs[0].lines))
	}
}

func TestHandleDangerEndKnownContactNotified(t *testing.T) {
	contactPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = []ContactInfo{{Username: "alice", IdentityPub: contactPub}}
	m.handleDangerEnd(shared.KnockPayload{
		Type:            "danger_end",
		FromUsername:    "alice",
		FromIdentityPub: contactPub,
		TargetDeviceID:  targetDeviceID,
	})
	if len(m.tabs[0].lines) != 1 {
		t.Fatalf("want 1 Console line after a danger_end from a known contact, found %d", len(m.tabs[0].lines))
	}
	if !m.dangerEndSeen[hex.EncodeToString(targetDeviceID)] {
		t.Error("dangerEndSeen should have been marked for this targetDeviceID")
	}
}

func TestHandleDangerBroadcastAfterDangerEndSuppressed(t *testing.T) {
	contactPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = []ContactInfo{{Username: "alice", IdentityPub: contactPub}}

	// The danger_end (final) arrives BEFORE the danger_broadcast (preliminary)
	// for the same device: the former makes a single hop, the latter a double
	// round trip via authority.
	m.handleDangerEnd(shared.KnockPayload{
		Type:            "danger_end",
		FromUsername:    "alice",
		FromIdentityPub: contactPub,
		TargetDeviceID:  targetDeviceID,
	})
	if len(m.tabs[0].lines) != 1 {
		t.Fatalf("want 1 line after danger_end, found %d", len(m.tabs[0].lines))
	}

	m.handleDangerBroadcast(shared.KnockPayload{
		Type:            "danger_broadcast",
		FromUsername:    "alice",
		FromIdentityPub: contactPub,
		TargetDeviceID:  targetDeviceID,
	})
	if len(m.tabs[0].lines) != 1 {
		t.Fatalf("a danger_broadcast arriving after the danger_end for the same device must not add a second misleading line, found %d", len(m.tabs[0].lines))
	}
}

func TestHandleDangerEndAckRemovesFromPendingEnds(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)

	m := newRemoteNukeTestModel(nil, nil)
	m.pendingDangerEnds = []DangerBroadcastPendingInfo{
		{TargetDeviceID: targetDeviceID, IdentityPubs: [][]byte{testPub("bob")}},
	}
	var confirmedPub []byte
	m.confirmDangerEnd = func(devID, pub []byte) error {
		confirmedPub = pub
		return nil
	}

	m.handleDangerEndAck(shared.KnockPayload{
		Type:            "danger_end_ack",
		FromUsername:    "bob",
		FromIdentityPub: testPub("bob"),
		TargetDeviceID:  targetDeviceID,
	})

	if !bytes.Equal(confirmedPub, testPub("bob")) {
		t.Errorf("confirmDangerEnd not called with the right key, got %x", confirmedPub)
	}
	if len(m.pendingDangerEnds) != 0 {
		t.Fatalf("want 0 pending entries after the last ack, found %d", len(m.pendingDangerEnds))
	}
	// pendingDangerBroadcasts is an independent queue, must not be touched.
	if m.pendingDangerBroadcasts != nil {
		t.Error("handleDangerEndAck must not touch pendingDangerBroadcasts")
	}
}

func TestHandleRemoteNukeAckAlsoRegistersDangerEndQueue(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	contactPub, _, _ := ed25519.GenerateKey(rand.Reader)

	m := newRemoteNukeTestModel(nil, nil)
	m.contacts = []ContactInfo{{Username: "bob", IdentityPub: contactPub, NetAddr: "bob.onion"}}
	ack, rec := signedRemoteNukeAck(targetDeviceID)
	m.knownDevices = func() []DeviceRecordInfo { return []DeviceRecordInfo{rec} }
	var pendingPubs [][]byte
	m.setDangerEndPending = func(devID []byte, pubs [][]byte) error {
		pendingPubs = pubs
		return nil
	}

	m.handleRemoteNukeAck(ack)

	if len(pendingPubs) != 1 || !bytes.Equal(pendingPubs[0], contactPub) {
		t.Errorf("setDangerEndPending not called with the expected key: %x", pendingPubs)
	}
	if len(m.pendingDangerEnds) != 1 || !bytes.Equal(m.pendingDangerEnds[0].IdentityPubs[0], contactPub) {
		t.Errorf("in-memory pendingDangerEnds not updated: %+v", m.pendingDangerEnds)
	}
}

func TestExecuteRemoteNukeUsesAllIdentitiesContacts(t *testing.T) {
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	m := newRemoteNukeTestModel(nil, nil)
	called := 0
	m.allIdentitiesContacts = func() []AllIdentityContactsInfo {
		called++
		return []AllIdentityContactsInfo{
			{Username: "i1", IdentityPub: pub1, Contacts: nil, DHTagFn: nil},
			{Username: "i2", IdentityPub: pub2, Contacts: nil, DHTagFn: nil},
		}
	}

	cmd := m.executeRemoteNuke("", nil, targetDeviceID)
	if cmd == nil {
		t.Fatal("want a tea.Cmd from executeRemoteNuke")
	}
	msg := cmd()
	if _, ok := msg.(remoteNukeExecutedMsg); !ok {
		t.Fatalf("want remoteNukeExecutedMsg, got %T", msg)
	}
	if called != 1 {
		t.Errorf("want allIdentitiesContacts called once, called %d times", called)
	}
}

// runCmdTree runs cmd and, recursively, every sub-command of any resulting
// tea.BatchMsg — the same work the bubbletea runtime would do (in separate
// goroutines, here synchronous) for a tea.Batch(...) returned by
// Update()/its handlers.
func runCmdTree(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			runCmdTree(sub)
		}
	}
}

// TestApplyRelInitRefreshesRoomRegistry verifies that an incoming
// rel_init/rel_init_ack can update PeerRelIdentityPub even AFTER a room has
// already been registered as host with this contact (e.g. the peer restored
// from backup and regenerated its relationship keys while keeping the same
// transport IdentityPub) — the secret registers a RESOLVER
// (m.relKeysResolver), not a key pair: once applyRelInit persists the new key
// (persistCmd, run here as the runtime would after Update()), the next
// LookupSecret sees it immediately, with no separate refresh call needed.
func TestApplyRelInitRefreshesRoomRegistry(t *testing.T) {
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	myIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	reg := server.NewRoomRegistry()
	secret := []byte("shared-test-secret-of-32-bytes!!")
	oldPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bobDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	// fake "keystore": a mutex-protected map, read by the resolver and
	// written by updateContactRelKeys — reproduces the same real scheme
	// (resolver toward keystore.Keystore.RelKeysForDevice, asynchronous
	// persistence via TUIParams.UpdateContactRelKeys) without serializing a
	// real *keystore.Keystore.
	var storeMu sync.Mutex
	stored := map[string]RelKeyUpdate{
		string(bobDevicePub): {PeerRelIdentityPub: oldPeerPub, RelIdentityPriv: myIdentKey.Priv},
	}
	resolveFn := func(identityPub, devicePub []byte) (shared.RelPeerKey, shared.RelSigningKey, bool) {
		storeMu.Lock()
		defer storeMu.Unlock()
		u, ok := stored[string(devicePub)]
		if !ok {
			return shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		return shared.RelPeerKey{Pub: ed25519.PublicKey(u.PeerRelIdentityPub)}, shared.RelSigningKey{Priv: ed25519.PrivateKey(u.RelIdentityPriv)}, true
	}

	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"": {RelIdentityPriv: myIdentKey.Priv},
			},
		}},
		resolveRelKeysForDevice: resolveFn,
		updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error {
			storeMu.Lock()
			defer storeMu.Unlock()
			stored[string(upd.DevicePub)] = upd
			return nil
		},
	}
	reg.AddSecret("room-1", secret, "bob", bobPub, bobDevicePub, m.relKeysResolver(bobPub, bobDevicePub))

	newIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newIdentPub, newIdentMLKEM, newIdentMLDSA, err := shared.RelSigningKeyPublicParts(newIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	newContentPub, newContentMLKEM, newContentMLDSA, err := shared.RelSigningKeyPublicParts(newContentKey)
	if err != nil {
		t.Fatal(err)
	}

	ts := shared.NowTS()
	sig := shared.SignRelBootstrap(bobPriv, newIdentPub, newContentPub, bobDevicePub, "bob", ts)
	cmd := m.applyRelInit(shared.KnockPayload{
		Type:            "rel_init_ack",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelBootstrap: &shared.RelBootstrapPayload{
			IdentityPub:      newIdentPub,
			IdentityMLKEMPub: newIdentMLKEM,
			IdentityMLDSAPub: newIdentMLDSA,
			ContentPub:       newContentPub,
			ContentMLKEMPub:  newContentMLKEM,
			ContentMLDSAPub:  newContentMLDSA,
			DevicePub:        bobDevicePub,
			Ts:               ts,
			Sig:              sig,
		},
	})
	runCmdTree(cmd)

	nonce, _ := shared.RandomBytes(32)
	roomKey, err := shared.DeriveContactRoomKey(secret, shared.CurrentPeriod())
	if err != nil {
		t.Fatal(err)
	}
	proof := shared.ComputeRoomProof(roomKey, nonce)
	_, _, _, _, _, gotPeerKey, _, ok := reg.LookupSecret(nonce, proof)
	if !ok {
		t.Fatal("LookupSecret: want a match")
	}
	if string(gotPeerKey.Pub) != string(newIdentPub) {
		t.Errorf("peerKey not resolved live after the rel_init_ack: want %x, got %x", newIdentPub, gotPeerKey.Pub)
	}
	if string(gotPeerKey.Pub) == string(oldPeerPub) {
		t.Error("peerKey stayed the old one — the resolver doesn't read the updated state")
	}
}

// TestApplyRelInitPromotesPlaceholderDespiteExtraDevice verifies that the
// "" placeholder is always promoted to the real, just-arrived DevicePub,
// even when Devices already contains another entry (a state that should not
// occur for a single-device contact, but that a stricter guard would turn
// into a second orphan placeholder instead of consuming the existing one).
func TestApplyRelInitPromotesPlaceholderDespiteExtraDevice(t *testing.T) {
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	placeholderKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	otherDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	newDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"":                     {RelIdentityPriv: placeholderKey.Priv, RelContentPriv: placeholderKey.Priv},
				string(otherDevicePub): {RelIdentityConfirmedByPeer: true, RelContentConfirmedByPeer: true},
			},
		}},
		updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error { return nil },
	}

	newIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newIdentPub, newIdentMLKEM, newIdentMLDSA, err := shared.RelSigningKeyPublicParts(newIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	newContentPub, newContentMLKEM, newContentMLDSA, err := shared.RelSigningKeyPublicParts(newContentKey)
	if err != nil {
		t.Fatal(err)
	}

	ts := shared.NowTS()
	sig := shared.SignRelBootstrap(bobPriv, newIdentPub, newContentPub, newDevicePub, "bob", ts)
	cmd := m.applyRelInit(shared.KnockPayload{
		Type:            "rel_init",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelBootstrap: &shared.RelBootstrapPayload{
			IdentityPub:      newIdentPub,
			IdentityMLKEMPub: newIdentMLKEM,
			IdentityMLDSAPub: newIdentMLDSA,
			ContentPub:       newContentPub,
			ContentMLKEMPub:  newContentMLKEM,
			ContentMLDSAPub:  newContentMLDSA,
			DevicePub:        newDevicePub,
			Ts:               ts,
			Sig:              sig,
		},
	})
	runCmdTree(cmd)

	c := m.contacts[0]
	if _, hasPh := c.Devices[""]; hasPh {
		t.Error("the \"\" placeholder is still present: it was not promoted")
	}
	dev, ok := c.Devices[string(newDevicePub)]
	if !ok || dev == nil {
		t.Fatal("no entry created for the incoming real DevicePub")
	}
	if string(dev.RelIdentityPriv) != string(placeholderKey.Priv) {
		t.Error("the promoted entry doesn't carry the placeholder's keys: they were regenerated from scratch instead of reused")
	}
	if _, stillOther := c.Devices[string(otherDevicePub)]; !stillOther {
		t.Error("the pre-existing device's entry was removed: it should have stayed intact")
	}
	if len(c.Devices) != 2 {
		t.Errorf("len(Devices) = %d, want 2 (pre-existing device + promoted device)", len(c.Devices))
	}
}

// TestApplyRelInitDetectsConflict verifies that a rel_init/rel_init_ack
// arriving on an already-confirmed contact (RelInitConfirmedByPeer),
// proposing BOTH relationship keys different from the already-known ones,
// must never automatically overwrite PeerRelIdentityPub/PeerRelContentPub —
// the proposed keys are held in PendingPeerRel* until the user explicitly
// confirms (/sec-verify).
func TestApplyRelInitDetectsConflict(t *testing.T) {
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	myIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	myContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPeerIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPeerContentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bobDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	var pendingCalled bool
	var pendingArg PendingRelKeys
	var updateCalled bool

	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				string(bobDevicePub): {
					RelIdentityPriv:            myIdentKey.Priv,
					RelContentPriv:             myContentKey.Priv,
					PeerRelIdentityPub:         oldPeerIdentPub,
					PeerRelContentPub:          oldPeerContentPub,
					RelIdentityConfirmedByPeer: true,
					RelContentConfirmedByPeer:  true,
				},
			},
		}},
		setPendingRelKeys: func(pub []byte, pending PendingRelKeys) error {
			pendingCalled = true
			pendingArg = pending
			return nil
		},
		updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error {
			updateCalled = true
			return nil
		},
	}

	newIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newIdentPub, newIdentMLKEM, newIdentMLDSA, err := shared.RelSigningKeyPublicParts(newIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	newContentPub, newContentMLKEM, newContentMLDSA, err := shared.RelSigningKeyPublicParts(newContentKey)
	if err != nil {
		t.Fatal(err)
	}

	// Type "rel_init_ack" (not "rel_init"): the conflict branch for a request
	// would also respond with a tea.Batch(persistCmd, ack) — here the direct
	// persistCmd alone suffices, returned without wrapping for an ack
	// (terminal, no response owed).
	ts := shared.NowTS()
	sig := shared.SignRelBootstrap(bobPriv, newIdentPub, newContentPub, bobDevicePub, "bob", ts)
	cmd := m.applyRelInit(shared.KnockPayload{
		Type:            "rel_init_ack",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelBootstrap: &shared.RelBootstrapPayload{
			IdentityPub:      newIdentPub,
			IdentityMLKEMPub: newIdentMLKEM,
			IdentityMLDSAPub: newIdentMLDSA,
			ContentPub:       newContentPub,
			ContentMLKEMPub:  newContentMLKEM,
			ContentMLDSAPub:  newContentMLDSA,
			DevicePub:        bobDevicePub,
			Ts:               ts,
			Sig:              sig,
		},
	})
	if cmd == nil {
		t.Fatal("applyRelInit returned nil, want the persistCmd toward setPendingRelKeys")
	}
	cmd()

	c := m.contacts[0]
	dev, ok := c.SoleDevice()
	if !ok {
		t.Fatal("SoleDevice not found after applyRelInit")
	}
	if string(dev.PeerRelIdentityPub) != string(oldPeerIdentPub) {
		t.Errorf("PeerRelIdentityPub was overwritten automatically: want the old %x, got %x", oldPeerIdentPub, dev.PeerRelIdentityPub)
	}
	if string(dev.PeerRelContentPub) != string(oldPeerContentPub) {
		t.Errorf("PeerRelContentPub was overwritten automatically: want the old %x, got %x", oldPeerContentPub, dev.PeerRelContentPub)
	}
	if string(dev.PendingPeerRelIdentityPub) != string(newIdentPub) {
		t.Errorf("PendingPeerRelIdentityPub not populated correctly: want %x, got %x", newIdentPub, dev.PendingPeerRelIdentityPub)
	}
	if string(dev.PendingPeerRelContentPub) != string(newContentPub) {
		t.Errorf("PendingPeerRelContentPub not populated correctly: want %x, got %x", newContentPub, dev.PendingPeerRelContentPub)
	}
	if c.TrustLevel() != TrustDanger {
		t.Errorf("TrustLevel = %v, want TrustDanger", c.TrustLevel())
	}
	if updateCalled {
		t.Error("updateContactRelKeys called: the conflict must go ONLY through setPendingRelKeys, never apply directly")
	}
	if !pendingCalled {
		t.Fatal("setPendingRelKeys not called")
	}
	if string(pendingArg.IdentityPub) != string(newIdentPub) || string(pendingArg.ContentPub) != string(newContentPub) {
		t.Error("the PendingRelKeys passed to setPendingRelKeys doesn't match the proposed keys")
	}
}

// TestApplyRelInitRejectsUnsignedOrInvalidSig verifies that a rel_init/
// rel_init_ack lacking a valid Ed25519 signature against the sender's root
// IdentityKey (already known, Contact.IdentityPub) is discarded before
// touching any field — never applied, never put in Pending. Covers three
// cases: missing Sig, Sig signed with the wrong key, valid Sig but over a
// payload different from the one declared (tampering).
func TestApplyRelInitRejectsUnsignedOrInvalidSig(t *testing.T) {
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	newDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	newIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newIdentPub, newIdentMLKEM, newIdentMLDSA, err := shared.RelSigningKeyPublicParts(newIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	newContentPub, newContentMLKEM, newContentMLDSA, err := shared.RelSigningKeyPublicParts(newContentKey)
	if err != nil {
		t.Fatal(err)
	}

	newModel := func() *model {
		return &model{
			myUsername: "alice",
			contacts: []ContactInfo{{
				Username:    "bob",
				IdentityPub: bobPub,
			}},
			updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error {
				t.Error("updateContactRelKeys called: an unauthenticated rel_init must never apply anything")
				return nil
			},
		}
	}
	base := func() shared.RelBootstrapPayload {
		return shared.RelBootstrapPayload{
			IdentityPub:      newIdentPub,
			IdentityMLKEMPub: newIdentMLKEM,
			IdentityMLDSAPub: newIdentMLDSA,
			ContentPub:       newContentPub,
			ContentMLKEMPub:  newContentMLKEM,
			ContentMLDSAPub:  newContentMLDSA,
			DevicePub:        newDevicePub,
		}
	}
	assertRejected := func(t *testing.T, m *model, rb shared.RelBootstrapPayload) {
		t.Helper()
		cmd := m.applyRelInit(shared.KnockPayload{
			Type:            "rel_init",
			FromUsername:    "bob",
			FromIdentityPub: bobPub,
			RelBootstrap:    &rb,
		})
		if cmd != nil {
			runCmdTree(cmd)
		}
		if len(m.contacts[0].Devices) != 0 {
			t.Error("an unauthenticated rel_init still created/changed a Devices entry")
		}
	}

	t.Run("missing sig", func(t *testing.T) {
		rb := base()
		assertRejected(t, newModel(), rb)
	})
	t.Run("sig signed with the wrong key", func(t *testing.T) {
		rb := base()
		ts := shared.NowTS()
		rb.Ts = ts
		rb.Sig = shared.SignRelBootstrap(wrongPriv, newIdentPub, newContentPub, newDevicePub, "bob", ts)
		assertRejected(t, newModel(), rb)
	})
	t.Run("valid sig but over a different payload (tampering)", func(t *testing.T) {
		rb := base()
		ts := shared.NowTS()
		// Signature computed over a ContentPub different from the one in the
		// declared payload: simulates an attacker intercepting a valid rel_init
		// and swapping ContentPub before forwarding it.
		tamperedContentPub, _, _ := ed25519.GenerateKey(rand.Reader)
		rb.Ts = ts
		rb.Sig = shared.SignRelBootstrap(bobPriv, newIdentPub, tamperedContentPub, newDevicePub, "bob", ts)
		assertRejected(t, newModel(), rb)
	})
}

// TestApplyRelInitAcceptsValidSigFromKnownDevicePub verifies the positive
// complementary case: a valid signature, computed with the sender's root
// IdentityPrivKey exactly over the declared fields, is accepted and applies
// the proposed keys — the signature check doesn't block the legitimate
// path (also covered by
// TestApplyRelInitPromotesPlaceholderDespiteExtraDevice, here isolated
// without a preexisting placeholder/device).
func TestApplyRelInitAcceptsValidSigFromKnownDevicePub(t *testing.T) {
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	newDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)

	newIdentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newContentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newIdentPub, newIdentMLKEM, newIdentMLDSA, err := shared.RelSigningKeyPublicParts(newIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	newContentPub, newContentMLKEM, newContentMLDSA, err := shared.RelSigningKeyPublicParts(newContentKey)
	if err != nil {
		t.Fatal(err)
	}

	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
		}},
		updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error { return nil },
	}

	ts := shared.NowTS()
	sig := shared.SignRelBootstrap(bobPriv, newIdentPub, newContentPub, newDevicePub, "bob", ts)
	cmd := m.applyRelInit(shared.KnockPayload{
		Type:            "rel_init",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelBootstrap: &shared.RelBootstrapPayload{
			IdentityPub:      newIdentPub,
			IdentityMLKEMPub: newIdentMLKEM,
			IdentityMLDSAPub: newIdentMLDSA,
			ContentPub:       newContentPub,
			ContentMLKEMPub:  newContentMLKEM,
			ContentMLDSAPub:  newContentMLDSA,
			DevicePub:        newDevicePub,
			Ts:               ts,
			Sig:              sig,
		},
	})
	runCmdTree(cmd)

	dev, ok := m.contacts[0].Devices[string(newDevicePub)]
	if !ok || dev == nil {
		t.Fatal("no entry created for the authenticated device")
	}
	if string(dev.PeerRelIdentityPub) != string(newIdentPub) || string(dev.PeerRelContentPub) != string(newContentPub) {
		t.Error("the proposed keys were not applied despite a valid signature")
	}
}

// TestApplyRelRotateRejectsStaleReplay verifies that a rotation request
// (rel_identity_rotate) correctly signed with the peer's sibling ContentKey,
// but with a `ts` outside the freshness window
// (shared.TsFreshnessWindow), is discarded without applying any update —
// even though the signature verifies in full. A captured old rotation
// message, whose signature stays valid as long as the peer's sibling
// ContentKey never changes, must not be replayable later to force a
// silent downgrade.
func TestApplyRelRotateRejectsStaleReplay(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bobDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	// PeerRelContentPub/Priv: the PEER's (bob's) ContentKey, known locally —
	// this is what bob uses to sign its own IdentityKey rotation.
	peerContentPub, peerContentPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPeerIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)

	dev := &keystore.DeviceRelation{
		PeerRelIdentityPub:         oldPeerIdentPub,
		PeerRelContentPub:          peerContentPub,
		RelIdentityConfirmedByPeer: true,
		RelContentConfirmedByPeer:  true,
	}
	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices:     map[string]*keystore.DeviceRelation{string(bobDevicePub): dev},
		}},
	}

	newIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	staleTs := "2020-01-01T00:00:00Z"
	m.applyRelRotate(shared.KnockPayload{
		Type:            "rel_identity_rotate",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelRotate: &shared.RelRotatePayload{
			NewPub:    newIdentPub,
			Sig:       shared.SignRelKeyRotation(peerContentPriv, newIdentPub, "bob", staleTs),
			Ts:        staleTs,
			DevicePub: bobDevicePub,
		},
	})

	if string(dev.PeerRelIdentityPub) != string(oldPeerIdentPub) {
		t.Fatalf("PeerRelIdentityPub updated by a request with an expired ts (replay not blocked): want %x, got %x", oldPeerIdentPub, dev.PeerRelIdentityPub)
	}
}

// TestApplyRelRotateAcceptsFreshRequest is the positive round-trip twin of
// TestApplyRelRotateRejectsStaleReplay: an identical request but with a
// fresh ts must be applied normally.
func TestApplyRelRotateAcceptsFreshRequest(t *testing.T) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bobDevicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	peerContentPub, peerContentPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPeerIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)

	dev := &keystore.DeviceRelation{
		PeerRelIdentityPub:         oldPeerIdentPub,
		PeerRelContentPub:          peerContentPub,
		RelIdentityConfirmedByPeer: true,
		RelContentConfirmedByPeer:  true,
	}
	m := &model{
		myUsername: "alice",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices:     map[string]*keystore.DeviceRelation{string(bobDevicePub): dev},
		}},
		updateContactRelKeys: func(pub []byte, upd RelKeyUpdate) error { return nil },
	}

	newIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	freshTs := shared.NowTS()
	m.applyRelRotate(shared.KnockPayload{
		Type:            "rel_identity_rotate",
		FromUsername:    "bob",
		FromIdentityPub: bobPub,
		RelRotate: &shared.RelRotatePayload{
			NewPub:    newIdentPub,
			Sig:       shared.SignRelKeyRotation(peerContentPriv, newIdentPub, "bob", freshTs),
			Ts:        freshTs,
			DevicePub: bobDevicePub,
		},
	})

	if string(dev.PeerRelIdentityPub) != string(newIdentPub) {
		t.Fatalf("PeerRelIdentityPub not updated by a fresh, valid request: want %x, got %x", newIdentPub, dev.PeerRelIdentityPub)
	}
}

// TestParseMessageSigInvalidTriggersSelfHeal verifies that a content
// signature that fails to verify against the ContentKey known for the
// contact must clear RelInitConfirmedByPeer and call
// resetRelInitConfirmed (self-heal, same mechanism already used for
// client.ErrInvalidServerSig on the IdentityKey).
func TestParseMessageSigInvalidTriggersSelfHeal(t *testing.T) {
	senderKey := make([]byte, 32)
	rand.Read(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-content-sig-heal"

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)
	tab := &roomTab{cli: cli}

	bobPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// knownPub is the one "me" has in its contact book for bob — the signature
	// below is computed with a DIFFERENT key, so verification fails exactly as
	// with a misaligned peer ContentKey.
	knownPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cli.RegisterUser("uid-bob", "bob", bobPub)

	resetCh := make(chan []byte, 1)
	m := &model{
		myUsername:    "me",
		myIdentityPub: testPub("me"),
		tabs:          []*roomTab{tab},
		active:        0,
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"d": {
					PeerRelContentPub:         knownPub,
					RelContentConfirmedByPeer: true,
				},
			},
		}},
		resetRelInitConfirmed: func(pub, devicePub []byte, which string) error {
			if which != "content" {
				t.Errorf("resetRelInitConfirmed called with which=%q, want \"content\"", which)
			}
			resetCh <- append([]byte(nil), pub...)
			return nil
		},
	}

	enc, err := client.EncryptTestSealedFrame(chain0, 0, "bob", "hello", nil)
	if err != nil {
		t.Fatalf("EncryptTestSealedFrame: %v", err)
	}
	ts := "2026-09-06T12:00:00Z"
	sig := shared.SignRelMsg(wrongPriv, enc, ts, testKey("me"))
	frame := map[string]any{
		"kid":            keyID,
		"text":           enc,
		"idx":            float64(0),
		"from_user_id":   "uid-bob",
		"content_sig_ts": ts,
		"content_sigs": []any{
			map[string]any{"for": testKey("me"), "sig": base64.StdEncoding.EncodeToString(sig)},
		},
	}

	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine")
	}
	if line.sigStatus != sigFailed {
		t.Fatalf("sigStatus = %v, want sigFailed", line.sigStatus)
	}
	if dev, ok := m.contacts[0].SoleDevice(); ok && dev.RelContentConfirmedByPeer {
		t.Error("RelContentConfirmedByPeer not cleared by the self-heal")
	}

	select {
	case got := <-resetCh:
		if !bytes.Equal(got, bobPub) {
			t.Errorf("resetRelInitConfirmed called with pub=%x, want %x", got, bobPub)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resetRelInitConfirmed not called within the timeout")
	}
}

// TestParseMessageVerifiesAgainstAnyDeviceCandidateMultiDevice verifies the
// receiving-side fan-out: a contact with 2 known devices, a message signed
// with the SECOND device's ContentKey (never the first) — without `dp`
// resolved to an exact device (as in the twin test above,
// EncryptTestSealedFrame does not set it), contentPeerPubCandidatesFor must
// fall back to BOTH devices, and verification must succeed by trying each
// candidate until one matches, not stop at the first (wrong) attempt.
func TestParseMessageVerifiesAgainstAnyDeviceCandidateMultiDevice(t *testing.T) {
	senderKey := make([]byte, 32)
	rand.Read(senderKey)
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-content-sig-multidevice"

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)
	tab := &roomTab{cli: cli}

	bobPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// devA: the ContentKey known for bob's FIRST device — not the one the
	// message is actually signed with below.
	devAPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// devB: the ContentKey of the SECOND device — the real one, used to
	// compute the signature below.
	devBPub, devBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cli.RegisterUser("uid-bob", "bob", bobPub)

	m := &model{
		myUsername:    "me",
		myIdentityPub: testPub("me"),
		tabs:          []*roomTab{tab},
		active:        0,
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"devA": {PeerRelContentPub: devAPub, RelContentConfirmedByPeer: true},
				"devB": {PeerRelContentPub: devBPub, RelContentConfirmedByPeer: true},
			},
		}},
	}

	enc, err := client.EncryptTestSealedFrame(chain0, 0, "bob", "hello from devB", nil)
	if err != nil {
		t.Fatalf("EncryptTestSealedFrame: %v", err)
	}
	ts := "2026-09-10T12:00:00Z"
	sig := shared.SignRelMsg(devBPriv, enc, ts, testKey("me"))
	frame := map[string]any{
		"kid":            keyID,
		"text":           enc,
		"idx":            float64(0),
		"from_user_id":   "uid-bob",
		"content_sig_ts": ts,
		"content_sigs": []any{
			map[string]any{"for": testKey("me"), "sig": base64.StdEncoding.EncodeToString(sig)},
		},
	}

	line, _ := m.parseMessage(tab, 0, frame)
	if line == nil {
		t.Fatal("want a chatLine")
	}
	if line.sigStatus != sigOK {
		t.Fatalf("sigStatus = %v, want sigOK (devB's signature must verify among the fan-out candidates)", line.sigStatus)
	}
	wantHex := fmt.Sprintf("%x", devBPub)
	if len(wantHex) > 8 {
		wantHex = wantHex[len(wantHex)-8:]
	}
	if line.contentKeyTag != "REL:"+wantHex {
		t.Errorf("contentKeyTag = %q, want %q (it must identify devB, not devA)", line.contentKeyTag, "REL:"+wantHex)
	}
}

// TestBuildContentSigningKeysFanOutMultiDevice verifies that
// buildContentSigningKeys produces ONE signature for EVERY device of the
// recipient that has its own ContentKey established — not only the first
// one found: the content_sigs wire format already supports multiple
// entries with the same "for", used here for the fan-out with no format
// change.
func TestBuildContentSigningKeysFanOutMultiDevice(t *testing.T) {
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	m := &model{
		myUsername: "me",
		contacts: []ContactInfo{{
			Username:    "bob",
			IdentityPub: bobPub,
			Devices: map[string]*keystore.DeviceRelation{
				"devA": {RelContentPriv: privA},
				"devB": {RelContentPriv: privB},
			},
		}},
	}
	tab := &roomTab{groupMembers: []GroupMember{{Username: "bob", IdentityPub: bobPub}}}

	keys := m.buildContentSigningKeys(tab)
	got := keys[client.MemberKeyOf(bobPub)]
	if len(got) != 2 {
		t.Fatalf("buildContentSigningKeys[\"bob\"] has %d keys, want 2 (one per device)", len(got))
	}
	seen := map[string]bool{string(privA): false, string(privB): false}
	for _, k := range got {
		if _, ok := seen[string(k.Priv)]; !ok {
			t.Fatalf("unexpected key in the fan-out: %x", k.Priv)
		}
		seen[string(k.Priv)] = true
	}
	for privHex, found := range seen {
		if !found {
			t.Errorf("device key missing from the fan-out: %x", []byte(privHex))
		}
	}
}
