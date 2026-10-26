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
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// writeRandomFile creates name in in's directory (the file browser's
// starting folder) with size random bytes, returning its sha256.
func writeRandomFile(t *testing.T, in *Instance, name string, size int) [32]byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.Dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

// sendFile runs /grp-file-send in room: picks name in the file browser
// through its filter, confirms the recipient picker if shown (all
// preselected), and confirms the speed popup — warp selects the second
// speed, noCompress toggles compression off.
func sendFile(t *testing.T, from *Instance, room, name string, warp, noCompress bool) {
	t.Helper()
	from.Focus(room)
	from.Send("/grp-file-send")
	from.WaitScreen(`choose file to send — `, shortWait)
	from.Type(name)
	from.Key("enter")
	from.WaitScreenMatch(`recipients — Space deselects|sending speed`, shortWait)
	if regexp.MustCompile(`recipients — Space deselects`).MatchString(from.Screen()) {
		from.Key("enter")
		from.WaitScreen(`sending speed`, shortWait)
	}
	if warp {
		from.Key("down")
	}
	if noCompress {
		from.Key("tab")
	}
	from.Key("enter")
}

// receiveFile accepts the incoming-file popup from sender for name and
// saves it, under its proposed name, in the receiver's starting folder.
// Returns the saved file's sha256.
func receiveFile(t *testing.T, to *Instance, sender, name string) [32]byte {
	t.Helper()
	to.WaitScreen(`(?s)INCOMING FILE.*from:\s+`+regexp.QuoteMeta(sender)+`.*name:\s+`+regexp.QuoteMeta(name), longWait)
	to.Key("enter")
	to.WaitScreen(`name of the received file — editable`, longWait)
	to.Key("enter")
	to.WaitScreen(`save "`+regexp.QuoteMeta(name)+`" in — `, shortWait)
	to.Key("enter")
	path := filepath.Join(to.Dir, name)
	deadline := time.Now().Add(shortWait)
	for {
		if data, err := os.ReadFile(path); err == nil {
			return sha256.Sum256(data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s never saved", to.Name, path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestFileSendTwoMembers: a multi-chunk file reaches the other member
// byte for byte, once with the default speed and compression, once
// with warp speed and compression off.
func TestFileSendTwoMembers(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)

	cases := []struct {
		name             string
		size             int
		warp, noCompress bool
	}{
		{"slow.bin", 3 << 20, false, false},
		{"warp.bin", 3 << 20, true, true},
	}
	for _, c := range cases {
		want := writeRandomFile(t, alice, c.name, c.size)
		sendFile(t, alice, room, c.name, c.warp, c.noCompress)
		if got := receiveFile(t, bob, "alice", c.name); got != want {
			t.Errorf("%s: received content differs from the sent file", c.name)
		}
	}
}

// TestFileSendThreeMembers: one send to a three-member room reaches
// both other members intact.
func TestFileSendThreeMembers(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob, carol)

	want := writeRandomFile(t, alice, "shared.bin", 2<<20)
	sendFile(t, alice, room, "shared.bin", false, false)
	for _, in := range []*Instance{bob, carol} {
		if got := receiveFile(t, in, "alice", "shared.bin"); got != want {
			t.Errorf("%s: received content differs from the sent file", in.Name)
		}
	}
}

// offerContactCard has from share the card of contact with the member
// of room, and to accept the transfer. Returns once to holds the card,
// not yet saved.
func offerContactCard(t *testing.T, from, to *Instance, room, contact string) {
	t.Helper()
	from.Focus(room)
	from.Send("/grp-contact-send " + contact)
	from.WaitScreen(`Offband contact info for `+regexp.QuoteMeta(contact), shortWait)
	from.Type("phone 555-0100")
	from.Key("enter")
	from.WaitScreen(`sending speed`, shortWait)
	from.Key("enter")

	to.WaitScreen(`(?s)INCOMING FILE.*from:\s+`+regexp.QuoteMeta(from.Name), longWait)
	to.Key("enter")
	to.Wait("*", regexp.QuoteMeta(from.Name)+` wants to send you the contact `+regexp.QuoteMeta(contact), 0, longWait)
}

// sendContactCard is offerContactCard followed by to saving the contact
// with /cnt-save. Returns once to has the new contact.
func sendContactCard(t *testing.T, from, to *Instance, room, contact string) {
	t.Helper()
	offerContactCard(t, from, to, room, contact)
	to.Focus(room)
	consoleFrom := to.LineCount("Console")
	to.Send("/cnt-save")
	to.WaitScreen(`Local name \[default: `+regexp.QuoteMeta(contact)+`\]`, shortWait)
	to.Key("enter")
	to.Wait("Console", `contact added: `+regexp.QuoteMeta(contact), consoleFrom, shortWait)
}

// TestContactCardIntroduction: alice introduces bob and carol to each
// other by sending each one the other's card; bob and carol then become
// working contacts of their own — they open a room and talk.
func TestContactCardIntroduction(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)

	roomAB := OpenRoom(alice, bob)
	sendContactCard(t, alice, bob, roomAB, "carol")
	roomAC := OpenRoom(alice, carol)
	sendContactCard(t, alice, carol, roomAC, "bob")

	for _, c := range []struct {
		in    *Instance
		other string
	}{{bob, "carol"}, {carol, "bob"}} {
		got := c.in.WaitContact(c.other, func(Contact) bool { return true }, "present", shortWait)
		if got.IntroducedBy != "alice" {
			t.Errorf("%s: contact %s introduced_by = %q, want alice", c.in.Name, c.other, got.IntroducedBy)
		}
	}
	bob.WaitReady("carol")
	carol.WaitReady("bob")

	roomBC := OpenRoom(bob, carol)
	bob.Focus(roomBC)
	bob.Send("hi carol, alice introduced us")
	got := carol.Wait(roomBC, "^bob: hi carol, alice introduced us$", 0, shortWait)
	if got.Sig != "ok" {
		t.Errorf("carol received bob's message with sig %q, want ok", got.Sig)
	}
}
