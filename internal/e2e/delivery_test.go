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
	"maps"
	"regexp"
	"slices"
	"testing"
	"time"
)

// roomMessages returns the chat lines (non-system, with a username) of
// room, in display order.
func roomMessages(in *Instance, room string) []Line {
	in.t.Helper()
	var out []Line
	for _, l := range in.Lines(room, 0) {
		if !l.System && l.Username != "" {
			out = append(out, l)
		}
	}
	return out
}

// checkRoomHistory verifies that in's room shows exactly want (texts, in
// order, each once) and that their room sequence numbers are strictly
// increasing with no duplicates.
func checkRoomHistory(t *testing.T, in *Instance, room string, want []string) {
	t.Helper()
	msgs := roomMessages(in, room)
	var texts []string
	var seqs []uint64
	for _, l := range msgs {
		texts = append(texts, l.Username+": "+l.Text)
		seqs = append(seqs, l.GSeq)
	}
	if !slices.Equal(texts, want) {
		t.Errorf("%s: room history\n got  %q\n want %q", in.Name, texts, want)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Errorf("%s: room sequence numbers not strictly increasing: %v", in.Name, seqs)
			break
		}
	}
}

// waitAllAcked waits until every own message of sender in room has been
// acknowledged by each of by.
func waitAllAcked(t *testing.T, sender *Instance, room string, by ...string) {
	t.Helper()
	deadline := time.Now().Add(longWait)
	for {
		pending := 0
		for _, l := range roomMessages(sender, room) {
			if l.Username != sender.Name {
				continue
			}
			for _, u := range by {
				if !slices.Contains(l.AckedBy, u) {
					pending++
				}
			}
		}
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d acknowledgements still missing in %s", sender.Name, pending, room)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDeliveryStableAfterJoin: right after a join, no member may be
// reported as lost (user_left reason=lost).
func TestDeliveryStableAfterJoin(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)

	alice.Focus(room)
	alice.Send("first after join")
	bob.Wait(room, "^alice: first after join$", 0, shortWait)

	time.Sleep(10 * time.Second)
	lost := regexp.MustCompile(`left room .*\(connection lost\)|left room`)
	for _, in := range []*Instance{alice, bob} {
		for _, tab := range []string{"Console", room} {
			for _, l := range in.Lines(tab, 0) {
				if lost.MatchString(l.Text) {
					t.Errorf("%s/%s: %q", in.Name, tab, l.Text)
				}
			}
		}
		in.WaitUsers(room, []string{"alice", "bob"}, shortWait)
	}
}

// TestDeliveryPausedRecipient: the recipient is frozen (as a phone
// suspending the app) while messages are sent; once resumed it receives
// all of them, in order, exactly once.
func TestDeliveryPausedRecipient(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)

	bob.Pause()
	var want []string
	for i := 1; i <= 5; i++ {
		text := fmt.Sprintf("while paused %d", i)
		alice.Send(text)
		want = append(want, "alice: "+text)
	}
	time.Sleep(3 * time.Second)
	bob.Resume()

	bob.Wait(room, "^alice: while paused 5$", 0, longWait)
	waitAllAcked(t, alice, room, "bob")
	checkRoomHistory(t, bob, room, want)
	checkRoomHistory(t, alice, room, want)
}

// TestDeliveryPausedSender: the sender freezes right after sending,
// before or while its own self-echo comes back. The message must reach
// the recipient once, and the sender must still see it confirmed (room
// sequence number and acknowledgement) after resuming.
func TestDeliveryPausedSender(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)

	alice.Send("sent then frozen")
	alice.Pause()
	time.Sleep(5 * time.Second)
	alice.Resume()

	bob.Wait(room, "^alice: sent then frozen$", 0, longWait)
	waitAllAcked(t, alice, room, "bob")
	time.Sleep(2 * time.Second)
	checkRoomHistory(t, bob, room, []string{"alice: sent then frozen"})
	checkRoomHistory(t, alice, room, []string{"alice: sent then frozen"})
}

// TestDeliveryBurst: many messages typed back to back from both sides,
// beyond the 5-slot backpressure window and the sender_key rotation
// threshold (25 messages), all arrive, each once, in the same order on
// both sides.
func TestDeliveryBurst(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)
	bob.Focus(room)

	const n = 30
	for i := 1; i <= n; i++ {
		alice.Send(fmt.Sprintf("a%02d", i))
		bob.Send(fmt.Sprintf("b%02d", i))
	}
	alice.Wait(room, fmt.Sprintf("^bob: b%02d$", n), 0, longWait)
	bob.Wait(room, fmt.Sprintf("^alice: a%02d$", n), 0, longWait)
	waitAllAcked(t, alice, room, "bob")
	waitAllAcked(t, bob, room, "alice")

	// Both sides must agree on one room order, given by the room
	// sequence numbers, the display order may legitimately differ
	// between sides only if it still follows gseq.
	order := func(in *Instance) []string {
		msgs := roomMessages(in, room)
		slices.SortStableFunc(msgs, func(a, b Line) int { return int(a.GSeq) - int(b.GSeq) })
		var out []string
		for _, l := range msgs {
			out = append(out, fmt.Sprintf("%d %s: %s", l.GSeq, l.Username, l.Text))
		}
		return out
	}
	ao, bo := order(alice), order(bob)
	if len(ao) != 2*n || len(bo) != 2*n {
		t.Fatalf("messages: alice sees %d, bob sees %d, want %d each", len(ao), len(bo), 2*n)
	}
	if !slices.Equal(ao, bo) {
		t.Errorf("room order differs:\n alice %q\n bob   %q", ao, bo)
	}
	for _, in := range []*Instance{alice, bob} {
		seen := map[uint64]bool{}
		for _, l := range roomMessages(in, room) {
			if seen[l.GSeq] {
				t.Errorf("%s: duplicate gseq %d", in.Name, l.GSeq)
			}
			seen[l.GSeq] = true
			if l.Username != in.Name && l.Sig != "ok" {
				t.Errorf("%s: %q has sig %q", in.Name, l.Text, l.Sig)
			}
		}
	}
}

// TestDeliveryReencryptAfterTTL: the recipient stays frozen beyond the
// message TTL, so the sender re-encrypts its unacknowledged messages
// under a new sender_key generation. Once resumed, the recipient shows
// each message exactly once, whichever copy it decrypts first, and the
// sender sees all of them acknowledged.
func TestDeliveryReencryptAfterTTL(t *testing.T) {
	r := NewRun(t)
	r.Config = maps.Clone(FastTimers)
	r.Config["message_ttl"] = "6s"
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)

	bob.Pause()
	var want []string
	for i := 1; i <= 3; i++ {
		text := fmt.Sprintf("before ttl %d", i)
		alice.Send(text)
		want = append(want, "alice: "+text)
	}
	time.Sleep(15 * time.Second)
	bob.Resume()

	bob.Wait(room, "^alice: before ttl 3$", 0, longWait)
	waitAllAcked(t, alice, room, "bob")
	time.Sleep(2 * time.Second)
	checkRoomHistory(t, bob, room, want)
	checkRoomHistory(t, alice, room, want)

	// The room keeps working in both directions on the new generation.
	bob.Focus(room)
	bob.Send("after ttl")
	alice.Wait(room, "^bob: after ttl$", 0, shortWait)
	alice.Send("after ttl too")
	bob.Wait(room, "^alice: after ttl too$", 0, shortWait)
}
