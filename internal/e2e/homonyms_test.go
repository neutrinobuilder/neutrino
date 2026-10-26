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

//go:build neutrino_agent

package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// homonymName matches a member name disambiguated by its key fingerprint.
var homonymName = regexp.MustCompile(`^bob ·[0-9a-f]{8}$`)

// addContactNamed makes a add b through /cnt-add with b's URI, saving it
// under localName.
func addContactNamed(a, b *Instance, localName string) {
	a.t.Helper()
	from := a.LineCount("Console")
	a.Send("/cnt-add " + b.URI())
	a.WaitScreen(`Save this contact\? \[Y/n\]`, shortWait)
	a.Key("enter")
	a.WaitScreen(`Local name \[default: `+regexp.QuoteMeta(b.Name)+`\]`, shortWait)
	a.Send(localName)
	a.Wait("Console", `contact added: .*`+regexp.QuoteMeta(localName), from, shortWait)
}

// waitReadyCount waits until n contacts named username have both
// relationship keys confirmed.
func waitReadyCount(t *testing.T, in *Instance, username string, n int) {
	t.Helper()
	deadline := time.Now().Add(longWait)
	for {
		ready := 0
		for _, c := range in.Contacts() {
			if c.Username == username && c.ReadyDevices > 0 {
				ready++
			}
		}
		if ready == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d contacts named %s ready, want %d", in.Name, ready, username, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitRoomUsers waits until in's tab room lists n users and returns them.
func waitRoomUsers(t *testing.T, in *Instance, room string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(longWait)
	for {
		if tab, ok := in.State().Room(room); ok && len(tab.Users) == n {
			return tab.Users
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: room %s never listed %d users\n--- screen ---\n%s", in.Name, room, n, in.screenOrErr())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestRoomHomonymMembers: two members with the same username but
// different identity keys are two distinct members of the same room,
// each listed, shown and acknowledging on its own, told apart by its key
// fingerprint, also by the member who shares their name.
func TestRoomHomonymMembers(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob1 := r.StartAs("bob-1", "bob")
	bob2 := r.StartAs("bob-2", "bob")
	addContactNamed(alice, bob1, "bobone")
	addContactNamed(alice, bob2, "bobtwo")
	AddContact(bob1, alice)
	AddContact(bob2, alice)
	waitReadyCount(t, alice, "bob", 2)
	bob1.WaitReady("alice")
	bob2.WaitReady("alice")

	alice.Send("/grp-invite bobone bobtwo")
	room := ""
	for _, m := range []*Instance{bob1, bob2} {
		sub := m.WaitScreenMatch(`alice invites you to group (\w+)`, longWait)
		if room == "" {
			room = sub[1]
		} else if sub[1] != room {
			t.Fatalf("the two bobs were invited to different groups: %s, %s", room, sub[1])
		}
		m.Key("enter")
	}

	users := waitRoomUsers(t, alice, room, 3)
	var bobs []string
	for _, u := range users {
		if u != "alice" {
			bobs = append(bobs, u)
		}
	}
	if len(bobs) != 2 || bobs[0] == bobs[1] || !homonymName.MatchString(bobs[0]) || !homonymName.MatchString(bobs[1]) {
		t.Fatalf("alice: the two bobs are not told apart: %v", users)
	}
	waitRoomUsers(t, bob1, room, 3)
	waitRoomUsers(t, bob2, room, 3)

	alice.Focus(room)
	alice.Send("to both bobs")
	waitOwnLine(t, alice, room, "to both bobs", func(l Line) bool { return len(l.AckedBy) == 2 }, "acknowledged by both bobs")
	for _, l := range alice.Lines(room, 0) {
		if l.Username == alice.Name && l.Text == "to both bobs" && l.AckedBy[0] == l.AckedBy[1] {
			t.Errorf("the two acks are not told apart: %v", l.AckedBy)
		}
	}

	bob1.Focus(room)
	bob1.Send("from the first")
	first := alice.Wait(room, `^bob ·[0-9a-f]{8}: from the first$`, 0, shortWait)
	bob2.Focus(room)
	bob2.Send("from the second")
	second := alice.Wait(room, `^bob ·[0-9a-f]{8}: from the second$`, 0, shortWait)
	if first.Username == second.Username {
		t.Errorf("alice: messages from the two bobs carry the same name %q", first.Username)
	}

	// Each bob sees the other as a namesake of itself, never as itself.
	other := bob2.Wait(room, `: from the first$`, 0, shortWait)
	if !homonymName.MatchString(other.Username) || strings.EqualFold(other.Username, bob2.Name) {
		t.Errorf("bob-2 shows bob-1's message as %q", other.Username)
	}
	if other.Username != first.Username {
		t.Errorf("bob-1 is %q for bob-2 but %q for alice: the fingerprint must be the same", other.Username, first.Username)
	}
}
