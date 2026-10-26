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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"
)

// TestBasePairRoomMessages: two identities become mutual contacts, open
// a two-member room and exchange messages both ways. Every received
// message must carry a valid signature, the same room sequence number
// on both sides, and be acknowledged back to its sender.
func TestBasePairRoomMessages(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")

	Pair(alice, bob)
	room := OpenRoom(alice, bob)

	exchange := []struct {
		from, to *Instance
		text     string
	}{
		{alice, bob, "hello bob"},
		{bob, alice, "hello alice"},
		{alice, bob, "second from alice"},
		{bob, alice, "second from bob"},
	}
	var seqs []uint64
	for _, m := range exchange {
		m.from.Focus(room)
		from := m.to.LineCount(room)
		m.from.Send(m.text)
		got := m.to.Wait(room, "^"+m.from.Name+": "+regexp.QuoteMeta(m.text)+"$", from, shortWait)
		if got.Sig != "ok" {
			t.Errorf("%s received %q with sig %q, want ok", m.to.Name, m.text, got.Sig)
		}
		if got.RelTag == "" {
			t.Errorf("%s received %q without a REL tag", m.to.Name, m.text)
		}
		if got.GSeq == 0 {
			t.Errorf("%s received %q without a room sequence number", m.to.Name, m.text)
		}
		seqs = append(seqs, got.GSeq)

		own := m.from.Wait(room, "^"+m.from.Name+": "+regexp.QuoteMeta(m.text)+"$", 0, shortWait)
		if own.Sig != "own" {
			t.Errorf("%s's own %q has sig %q, want own", m.from.Name, m.text, own.Sig)
		}
		waitOwnLine(t, m.from, room, m.text, func(l Line) bool {
			return l.GSeq == got.GSeq && slices.Contains(l.AckedBy, m.to.Name)
		}, "gseq "+strconv.FormatUint(got.GSeq, 10)+" acknowledged by "+m.to.Name)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Errorf("room sequence numbers %v not consecutive", seqs)
			break
		}
	}
}

// TestBaseQuitAndRestart: /quit withdraws the agent socket and the
// published address; a restart logs into the same keystore and keeps
// the address book.
func TestBaseQuitAndRestart(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	published, _ := filepath.Glob(filepath.Join(r.loopDir, "*.onion"))
	if len(published) != 2 {
		t.Fatalf("published addresses = %v, want 2", published)
	}

	alice.Quit()
	if _, err := os.Stat(alice.sockPath()); !os.IsNotExist(err) {
		t.Errorf("agent socket still present after /quit: %v", err)
	}
	published, _ = filepath.Glob(filepath.Join(r.loopDir, "*.onion"))
	if len(published) != 1 {
		t.Errorf("published addresses after /quit = %v, want only bob's", published)
	}

	alice.Restart()
	var contacts string
	for _, tab := range alice.State().Tabs {
		if tab.Kind == "contacts" {
			contacts = tab.Name
		}
	}
	alice.Focus(contacts)
	alice.WaitScreen(`"bob\s*"`, shortWait)

	// The restarted alice is reachable again: a room still opens.
	OpenRoom(alice, bob)
}

// waitOwnLine polls sender's own line with text until cond holds.
func waitOwnLine(t *testing.T, in *Instance, room, text string, cond func(Line) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(shortWait)
	for {
		for _, l := range in.Lines(room, 0) {
			if l.Username == in.Name && l.Text == text && cond(l) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: own message %q never reached: %s", in.Name, text, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestInviteRightAfterPairing: an invite sent before the relationship
// key exchange completes is queued and starts on its own once the
// contact is ready — the host must end up in the room exactly as if it
// had waited.
func TestInviteRightAfterPairing(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")

	AddContact(alice, bob)
	AddContact(bob, alice)
	room := OpenRoom(alice, bob)

	alice.Focus(room)
	from := bob.LineCount(room)
	alice.Send("after queued invite")
	bob.Wait(room, "^alice: after queued invite$", from, shortWait)
}
