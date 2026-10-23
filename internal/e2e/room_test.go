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
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"
)

// TestRoomInfoAndHealth: /grp-info lists the room's other members with
// the host marked, from the host's and from a member's side, and refuses
// a tab without members; /grp-health reports the local server's status.
func TestRoomInfoAndHealth(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	alice.Focus(room)
	alice.Send("/grp-info")
	alice.WaitScreen(`▸ room `+regexp.QuoteMeta(room)+`\s+\(host\)`, shortWait)
	alice.WaitScreen(`● bob\s`, shortWait)
	alice.WaitScreen(`● carol\s`, shortWait)
	alice.Key("esc")

	// carol isn't one of bob's contacts: listed, marked unknown.
	bob.Focus(room)
	bob.Send("/grp-info")
	bob.WaitScreen(`▸ room `+regexp.QuoteMeta(room)+`\s+\(host: alice\)`, shortWait)
	bob.WaitScreen(`● carol\s+\[UNKNOWN\]`, shortWait)
	bob.Key("esc")

	alice.Focus("Console")
	from := alice.LineCount("Console")
	alice.Send("/grp-info")
	alice.Wait("Console", `no participants to look up in this tab`, from, shortWait)

	from = alice.LineCount("Console")
	alice.Send("/grp-health")
	alice.Wait("Console", `health: \{.*"status":"ok"`, from, shortWait)
}

// TestRoomPing: /grp-ping measures the round trip to a member, by name
// and through the picker, and is refused outside a room.
func TestRoomPing(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)

	alice.Focus(room)
	alice.Send("/grp-ping bob")
	alice.WaitScreen(`ping bob via`, shortWait)
	alice.WaitScreen(`\(5/5 pong received\)`, longWait)
	alice.Key("esc")

	alice.Send("/grp-ping")
	alice.WaitScreen(`who do you want to ping\?`, shortWait)
	alice.Key("enter")
	alice.WaitScreen(`\(5/5 pong received\)`, longWait)
	alice.Key("esc")

	alice.Focus("Console")
	from := alice.LineCount("Console")
	alice.Send("/grp-ping bob")
	alice.Wait("Console", `usage: /grp-ping`, from, shortWait)
}

// TestRoomReplyReference: /msg N makes the next message an explicit
// reply to room message #N, seen as such by both sides; a number that
// isn't a shown message, or isn't a number, is refused.
func TestRoomReplyReference(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)
	bob.Focus(room)

	bob.Send("question")
	q := alice.Wait(room, "^bob: question$", 0, shortWait)

	alice.Send(fmt.Sprintf("/msg %d", q.GSeq))
	alice.WaitScreen(fmt.Sprintf(`↩ replying to #%d`, q.GSeq), shortWait)
	alice.Send("answer")
	got := bob.Wait(room, "^alice: answer$", 0, shortWait)
	if got.ReplyTo != q.GSeq {
		t.Errorf("bob sees the answer replying to #%d, want #%d", got.ReplyTo, q.GSeq)
	}
	waitOwnLine(t, alice, room, "answer", func(l Line) bool { return l.ReplyTo == q.GSeq }, fmt.Sprintf("reply to #%d", q.GSeq))

	// One-shot: the following message is a plain one.
	alice.Send("plain")
	if got := bob.Wait(room, "^alice: plain$", 0, shortWait); got.ReplyTo != 0 {
		t.Errorf("message after the reply still replies to #%d", got.ReplyTo)
	}

	from := alice.LineCount("Console")
	alice.Send("/msg 9999")
	alice.Wait("Console", `message #9999 not found in this room`, from, shortWait)
	from = alice.LineCount("Console")
	alice.Send("/msg abc")
	alice.Wait("Console", `"abc" is not a valid message number`, from, shortWait)
}

// TestRoomMsgAcks: /grp-msg-acks shows, for one of our messages, which
// members confirmed it and which haven't yet — a frozen member stays
// pending until it resumes.
func TestRoomMsgAcks(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)
	alice.Focus(room)

	carol.Pause()
	alice.Send("to both")
	waitOwnLine(t, alice, room, "to both", func(l Line) bool { return slices.Contains(l.AckedBy, "bob") }, "acknowledged by bob")

	alice.Send("/grp-msg-acks")
	alice.WaitScreen(`which message\?`, shortWait)
	alice.Key("enter")
	alice.WaitScreen(`confirmed by:[\s│]+bob[\s│]+not yet confirmed by:[\s│]+carol`, shortWait)
	alice.Key("esc")

	carol.Resume()
	waitAllAcked(t, alice, room, "bob", "carol")
	alice.Send("/grp-msg-acks")
	alice.WaitScreen(`which message\?`, shortWait)
	alice.Key("enter")
	alice.WaitScreen(`confirmed by:[\s│]+bob, carol[\s│]+not yet confirmed by:[\s│]+none`, shortWait)
	alice.Key("esc")

	alice.Focus("Console")
	from := alice.LineCount("Console")
	alice.Send("/grp-msg-acks")
	alice.Wait("Console", `usage: /grp-msg-acks`, from, shortWait)
}

// TestRoomExit: a member leaving with /grp-exit loses the room tab and
// disappears from the host's member list; a standard tab can't be
// closed.
func TestRoomExit(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)

	bob.Focus(room)
	bob.Send("/grp-exit")
	deadline := time.Now().Add(shortWait)
	for {
		if _, open := bob.State().Room(room); !open {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob still has the room tab after /grp-exit")
		}
		time.Sleep(100 * time.Millisecond)
	}
	alice.WaitUsers(room, []string{"alice"}, longWait)

	from := bob.LineCount("Console")
	bob.Focus("Console")
	bob.Send("/grp-exit")
	bob.Wait("Console", `the 'Console' tab cannot be closed`, from, shortWait)
}

// TestRoomReconnect: /grp-reconnect from a member and then from the host
// reconnects the room and renews the keys; messages keep flowing both
// ways with valid signatures, without waiting for a retransmission even
// when a message overtakes its new key. Outside a room it is refused.
func TestRoomReconnect(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)
	bob.Focus(room)

	exchange := func(round string) {
		t.Helper()
		alice.Send("from alice " + round)
		if got := bob.Wait(room, "^alice: from alice "+round+"$", 0, shortWait); got.Sig != "ok" {
			t.Errorf("%s: bob got alice's message with sig %q", round, got.Sig)
		}
		bob.Send("from bob " + round)
		if got := alice.Wait(room, "^bob: from bob "+round+"$", 0, shortWait); got.Sig != "ok" {
			t.Errorf("%s: alice got bob's message with sig %q", round, got.Sig)
		}
	}
	exchange("before")

	for _, in := range []*Instance{bob, alice} {
		from := in.LineCount("Console")
		in.Send("/grp-reconnect")
		in.Wait("Console", `reconnecting: `+regexp.QuoteMeta(room), from, shortWait)
		alice.WaitUsers(room, []string{"alice", "bob"}, longWait)
		bob.WaitUsers(room, []string{"alice", "bob"}, longWait)
		exchange("after " + in.Name)
	}

	alice.Focus("Console")
	from := alice.LineCount("Console")
	alice.Send("/grp-reconnect")
	alice.Wait("Console", `/grp-reconnect only available inside a room`, from, shortWait)
}
