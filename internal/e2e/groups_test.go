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
	"testing"
	"time"
)

// acceptInvite waits for host's invite popup on in, accepts it and
// returns the group ID it names.
func acceptInvite(in, host *Instance) string {
	in.t.Helper()
	sub := in.WaitScreenMatch(regexp.QuoteMeta(host.Name)+` invites you to group (\w+)`, longWait)
	in.Key("enter")
	return sub[1]
}

// exitRoom closes in's tab room with /grp-exit and waits until it's gone.
func exitRoom(t *testing.T, in *Instance, room string) {
	t.Helper()
	in.Focus(room)
	in.Send("/grp-exit")
	deadline := time.Now().Add(shortWait)
	for {
		if _, open := in.State().Room(room); !open {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still has the room tab %s after /grp-exit", in.Name, room)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestSavedGroupSaveRecallDelete: /grp-save names the current group
// (renaming its tab); after a restart /grp-recall reopens it under that
// name, re-inviting the saved members into the same group; /grp-del
// forgets it, by name and through the picker.
func TestSavedGroupSaveRecallDelete(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	alice.Focus(room)
	from := alice.LineCount("Console")
	alice.Send("/grp-save team")
	alice.Wait("Console", `group saved as «team» \(ID: `+regexp.QuoteMeta(room)+`\)`, from, shortWait)
	if _, ok := alice.State().Room("team"); !ok {
		t.Fatal("the room tab wasn't renamed to the saved name")
	}

	exitRoom(t, bob, room)
	exitRoom(t, carol, room)
	exitRoom(t, alice, "team")
	alice.Quit()
	alice.Restart()

	alice.Send("/grp-recall team")
	for _, m := range []*Instance{bob, carol} {
		if gid := acceptInvite(m, alice); gid != room {
			t.Fatalf("%s re-invited to group %s, want the saved %s", m.Name, gid, room)
		}
	}
	alice.WaitUsers("team", []string{"alice", "bob", "carol"}, longWait)
	bob.WaitUsers(room, []string{"alice", "bob", "carol"}, longWait)
	alice.Focus("team")
	alice.Send("together again")
	carol.Wait(room, "^alice: together again$", 0, shortWait)

	from = alice.LineCount("Console")
	alice.Send("/grp-del team")
	alice.Wait("Console", `group removed: team`, from, shortWait)

	// A second saved group, removed through the picker.
	alice.Focus("team")
	alice.Send("/grp-save crew")
	alice.Focus("Console")
	from = alice.LineCount("Console")
	alice.Send("/grp-del")
	alice.Type("crew")
	alice.Key("enter")
	alice.Wait("Console", `group removed: crew`, from, shortWait)

	from = alice.LineCount("Console")
	alice.Send("/grp-recall")
	alice.Wait("Console", `no saved group`, from, shortWait)
	from = alice.LineCount("Console")
	alice.Send("/grp-save other")
	alice.Wait("Console", `this room is not a group`, from, shortWait)
}

// TestGroupJoinWithoutInvite: /grp-join with no pending invite says so.
// A received invite always opens the accept/ignore popup, which takes
// the keyboard until answered, so the picker form can't be reached.
func TestGroupJoinWithoutInvite(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	from := alice.LineCount("Console")
	alice.Send("/grp-join")
	alice.Wait("Console", `no pending group invite`, from, shortWait)
}

// TestGroupReinvite: the host re-invites a member who left, by name and
// through the picker; with everyone connected there is nobody to
// re-invite, and a member can't re-invite.
func TestGroupReinvite(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	alice.Focus(room)
	roomFrom := alice.LineCount(room)
	alice.Send("/grp-reinvite")
	alice.Wait(room, `all members are already connected`, roomFrom, shortWait)

	exitRoom(t, carol, room)
	alice.WaitUsers(room, []string{"alice", "bob"}, longWait)
	roomFrom = alice.LineCount(room)
	alice.Send("/grp-reinvite carol")
	alice.Wait(room, `→ invite sent to carol \(carol\)`, roomFrom, longWait)
	acceptInvite(carol, alice)
	alice.WaitUsers(room, []string{"alice", "bob", "carol"}, longWait)

	exitRoom(t, carol, room)
	alice.WaitUsers(room, []string{"alice", "bob"}, longWait)
	alice.Send("/grp-reinvite")
	alice.Key("enter")
	acceptInvite(carol, alice)
	alice.WaitUsers(room, []string{"alice", "bob", "carol"}, longWait)
	carol.Focus(room)
	carol.Send("back again")
	bob.Wait(room, "^carol: back again$", 0, shortWait)

	bob.Focus(room)
	from := bob.LineCount("Console")
	bob.Send("/grp-reinvite carol")
	bob.Wait("Console", `/grp-reinvite available only to whoever opened the group`, from, shortWait)
}

// TestGroupAddMember: the host adds a contact to an open group of three;
// the new member joins and talks with everyone, the other members see
// them in the member list. A two-member room can't grow, an existing
// member can't be added twice, and a member can't add.
func TestGroupAddMember(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	dave := r.Start("dave")
	Pair(alice, bob)
	Pair(alice, carol)
	Pair(alice, dave)
	room := OpenRoom(alice, bob, carol)

	alice.Focus(room)
	from := alice.LineCount("Console")
	alice.Send("/grp-add-member bob")
	alice.Wait("Console", `bob \(bob\) is already a member of this group`, from, shortWait)

	roomFrom := alice.LineCount(room)
	alice.Send("/grp-add-member dave")
	if gid := acceptInvite(dave, alice); gid != room {
		t.Fatalf("dave invited to group %s, want %s", gid, room)
	}
	alice.Wait(room, `→ dave \(dave\) was invited and added to the group`, roomFrom, longWait)
	all := []string{"alice", "bob", "carol", "dave"}
	for _, in := range []*Instance{alice, bob, carol, dave} {
		in.WaitUsers(room, all, longWait)
	}
	dave.Focus(room)
	dave.Send("hello from dave")
	for _, in := range []*Instance{alice, bob, carol} {
		if got := in.Wait(room, "^dave: hello from dave$", 0, shortWait); got.Sig != "ok" {
			t.Errorf("%s got dave's message with sig %q", in.Name, got.Sig)
		}
	}
	bob.Focus(room)
	bob.Send("/grp-info")
	bob.WaitScreen(`● dave\s`, shortWait)
	bob.Key("esc")

	from = bob.LineCount("Console")
	bob.Send("/grp-add-member dave")
	bob.Wait("Console", `/grp-add-member available only to whoever opened the group`, from, shortWait)

	pair := OpenRoom(alice, dave)
	alice.Focus(pair)
	from = alice.LineCount("Console")
	alice.Send("/grp-add-member carol")
	alice.Wait("Console", `cannot add members to a two-person chat`, from, shortWait)
}

// TestGroupBan: the host removes a member for good, they drop out of
// the room and their own reconnection is refused, while the others keep
// talking; banning oneself or banning as a member is refused.
func TestGroupBan(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	alice.Focus(room)
	from := alice.LineCount("Console")
	alice.Send("/grp-ban alice")
	alice.Wait("Console", `you can't remove yourself`, from, shortWait)

	bob.Focus(room)
	from = bob.LineCount("Console")
	bob.Send("/grp-ban carol")
	bob.Wait("Console", `/grp-ban available only to whoever opened the group`, from, shortWait)

	roomFrom := alice.LineCount(room)
	alice.Send("/grp-ban carol")
	alice.Wait(room, `✗ carol \(carol\) was removed from the room$`, roomFrom, shortWait)
	alice.WaitUsers(room, []string{"alice", "bob"}, longWait)
	bob.WaitUsers(room, []string{"alice", "bob"}, longWait)

	carol.Focus(room)
	carol.Send("/grp-reconnect")
	time.Sleep(10 * time.Second)
	if users := roomUsers(alice, room); len(users) != 2 {
		t.Fatalf("after carol's reconnection attempt the host lists %v", users)
	}
	alice.Send("after the ban")
	bob.Wait(room, "^alice: after the ban$", 0, shortWait)
	for _, l := range carol.Lines(room, 0) {
		if l.Text == "after the ban" {
			t.Fatal("carol received a message sent after her ban")
		}
	}
}

// roomUsers returns the users in's tab room lists.
func roomUsers(in *Instance, room string) []string {
	tab, _ := in.State().Room(room)
	return tab.Users
}

// TestGroupPromote: two members introduced by the host's group promote
// each other to real contacts, both sides have to ask, and can then
// open a room of their own. Promoting an existing contact, or outside a
// room, is refused.
func TestGroupPromote(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	bob.Focus(room)
	from := bob.LineCount("Console")
	bob.Send("/grp-promote alice")
	bob.Wait("Console", `alice is already a contact`, from, shortWait)

	// The ephemeral key exchange between bob and carol may still be in
	// flight right after the join: retry until it is established.
	deadline := time.Now().Add(longWait)
	for {
		roomFrom := bob.LineCount(room)
		from := bob.LineCount("Console")
		bob.Send("/grp-promote carol")
		if waitAny(bob, []tabPattern{{room, `promotion-to-contact request sent to carol`, roomFrom}, {"Console", `key exchange with carol not complete yet`, from}}, shortWait) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob's ephemeral relationship with carol never established")
		}
		time.Sleep(time.Second)
	}
	if hasContact(bob, "carol") {
		t.Fatal("carol became bob's contact before carol promoted bob")
	}

	carol.Focus(room)
	from = carol.LineCount("Console")
	carol.Send("/grp-promote")
	carol.Key("enter")
	carol.Wait("Console", `contact added: bob`, from, longWait)
	bob.WaitContact("carol", func(Contact) bool { return true }, "added", longWait)
	bob.WaitReady("carol")
	carol.WaitReady("bob")

	direct := OpenRoom(bob, carol)
	bob.Focus(direct)
	bob.Send("now direct")
	if got := carol.Wait(direct, "^bob: now direct$", 0, shortWait); got.Sig != "ok" {
		t.Errorf("carol got bob's direct message with sig %q", got.Sig)
	}

	bob.Focus("Console")
	from = bob.LineCount("Console")
	bob.Send("/grp-promote carol")
	bob.Wait("Console", `/grp-promote is only available inside a room`, from, shortWait)
}

// tabPattern is one alternative waited for by waitAny.
type tabPattern struct {
	tab, pattern string
	from         int
}

// waitAny waits until one of the alternatives appears and returns its
// index, failing on timeout.
func waitAny(in *Instance, alts []tabPattern, timeout time.Duration) int {
	in.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for i, a := range alts {
			re := regexp.MustCompile(a.pattern)
			for _, l := range in.Lines(a.tab, a.from) {
				if re.MatchString(l.Text) {
					return i
				}
			}
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("%s: none of %+v appeared", in.Name, alts)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
