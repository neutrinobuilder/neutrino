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
)

// safetyCodePattern captures a safety code: five groups of eight base62
// characters.
const safetyCodePattern = `([0-9A-Za-z]{8}(?: [0-9A-Za-z]{8}){4})`

// TestSafetyNumberAndVerify: /sec-safety shows the same safety code on
// both sides, by name and through the picker; /sec-verify shows it for
// confirmation, "n" leaves the contact unverified, "y" marks it
// verified, also after a restart; /sec-unverify removes the mark, also
// after a restart.
func TestSafetyNumberAndVerify(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	alice.Send("/sec-safety bob")
	aliceCode := alice.WaitScreenMatch(`safety code with bob \(bob\):[\s│]+`+safetyCodePattern, shortWait)[1]
	alice.Key("esc")
	bob.Send("/sec-safety")
	bob.Type("alice")
	bob.Key("enter")
	bobCode := bob.WaitScreenMatch(`safety code with alice \(alice\):[\s│]+`+safetyCodePattern, shortWait)[1]
	bob.Key("esc")
	if aliceCode != bobCode {
		t.Fatalf("safety codes differ: alice sees %q, bob %q", aliceCode, bobCode)
	}

	from := alice.LineCount("Console")
	alice.Send("/sec-verify bob")
	alice.WaitScreen(regexp.QuoteMeta(aliceCode), shortWait)
	alice.WaitScreen(`Do you consider contact bob secure\? \[y/n\]`, shortWait)
	alice.Type("n")
	alice.Wait("Console", `Verification cancelled, the contact remains UNVERIFIED`, from, shortWait)
	if contactOf(t, alice, "bob").Verified {
		t.Fatal("bob verified after answering n")
	}

	from = alice.LineCount("Console")
	alice.Send("/sec-verify")
	alice.Type("bob")
	alice.Key("enter")
	alice.WaitScreen(`Do you consider contact bob secure\? \[y/n\]`, shortWait)
	alice.Type("y")
	alice.Wait("Console", `bob marked as Verified`, from, shortWait)
	alice.Quit()
	alice.Restart()
	if !contactOf(t, alice, "bob").Verified {
		t.Fatal("bob no longer verified after a restart")
	}
	if contactOf(t, bob, "alice").Verified {
		t.Error("alice's verification of bob marked alice verified on bob's side")
	}

	from = alice.LineCount("Console")
	alice.Send("/sec-unverify")
	alice.Type("bob")
	alice.Key("enter")
	alice.Wait("Console", `bob( \(bob\))? is no longer marked as Verified`, from, shortWait)
	from = alice.LineCount("Console")
	alice.Send("/sec-unverify bob")
	alice.Wait("Console", `bob( \(bob\))? is not marked as Verified`, from, shortWait)
	alice.Quit()
	alice.Restart()
	if contactOf(t, alice, "bob").Verified {
		t.Fatal("bob verified again after /sec-unverify and a restart")
	}
}

// TestPQCSign: /sec-pqc-sign turns ML-DSA-65 signing on and off for one
// room, the other member is told, and receives the messages sent in
// between with a valid PQC signature, the others without one. Outside a
// room, or with an unknown argument, it is refused.
func TestPQCSign(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	alice.Focus(room)

	roomFrom := alice.LineCount(room)
	alice.Send("/sec-pqc-sign")
	alice.Wait(room, `ML-DSA-65 signing off for this room`, roomFrom, shortWait)

	alice.Send("plain signature")
	if got := bob.Wait(room, "^alice: plain signature$", 0, shortWait); got.PQC {
		t.Error("message before /sec-pqc-sign on arrived with a PQC signature")
	}

	bobFrom := bob.LineCount(room)
	alice.Send("/sec-pqc-sign on")
	alice.Wait(room, `ML-DSA-65 signing on for this room`, roomFrom, shortWait)
	bob.Wait(room, `alice turned PQC \(ML-DSA-65\) signing on in this room`, bobFrom, shortWait)
	alice.Send("post-quantum")
	if got := bob.Wait(room, "^alice: post-quantum$", 0, shortWait); !got.PQC || got.Sig != "ok" {
		t.Errorf("message after /sec-pqc-sign on: pqc=%v sig=%q, want a valid PQC signature", got.PQC, got.Sig)
	}

	bobFrom = bob.LineCount(room)
	alice.Send("/sec-pqc-sign off")
	bob.Wait(room, `alice turned PQC \(ML-DSA-65\) signing off in this room`, bobFrom, shortWait)
	alice.Send("classic again")
	if got := bob.Wait(room, "^alice: classic again$", 0, shortWait); got.PQC {
		t.Error("message after /sec-pqc-sign off still carries a PQC signature")
	}

	from := alice.LineCount("Console")
	alice.Send("/sec-pqc-sign maybe")
	alice.Wait("Console", `usage: /sec-pqc-sign on \| /sec-pqc-sign off`, from, shortWait)
	alice.Focus("Console")
	from = alice.LineCount("Console")
	alice.Send("/sec-pqc-sign on")
	alice.Wait("Console", `/sec-pqc-sign only available inside a room`, from, shortWait)
}

// TestRotateRelKeys: rotating the per-relation IdentityKey (by name) and
// ContentKey (through the picker) toward a contact is confirmed by them,
// and a room opened afterwards carries messages with valid signatures
// both ways.
func TestRotateRelKeys(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	from := alice.LineCount("Console")
	alice.Send("/sec-rotate-rel-identity bob")
	alice.Wait("Console", `identity rotation started towards bob`, from, shortWait)
	alice.Wait("Console", `identity rotation confirmed by bob`, from, longWait)

	from = alice.LineCount("Console")
	alice.Send("/sec-rotate-rel-content")
	alice.Type("bob")
	alice.Key("enter")
	alice.Wait("Console", `content rotation started towards bob`, from, shortWait)
	alice.Wait("Console", `content rotation confirmed by bob`, from, longWait)

	room := OpenRoom(alice, bob)
	alice.Focus(room)
	bob.Focus(room)
	alice.Send("signed with new keys")
	if got := bob.Wait(room, "^alice: signed with new keys$", 0, shortWait); got.Sig != "ok" {
		t.Errorf("bob got alice's message with sig %q", got.Sig)
	}
	bob.Send("reply to new keys")
	if got := alice.Wait(room, "^bob: reply to new keys$", 0, shortWait); got.Sig != "ok" {
		t.Errorf("alice got bob's message with sig %q", got.Sig)
	}
}

// TestRotateRootKey: /sec-rotate-key needs the literal confirmation;
// with it the root IdentityKey changes, every contact adopts alice's new
// network address, and rooms opened afterwards in either direction work
// with valid signatures, also after alice restarts.
func TestRotateRootKey(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	oldAddr := contactOf(t, bob, "alice").NetAddr

	from := alice.LineCount("Console")
	alice.Send("/sec-rotate-key")
	alice.Wait("Console", "root rotation: type exactly `/sec-rotate-key ROTATE` to confirm", from, shortWait)

	from = alice.LineCount("Console")
	bobFrom := bob.LineCount("Console")
	carolFrom := carol.LineCount("Console")
	alice.Send("/sec-rotate-key ROTATE")
	alice.Wait("Console", `root rotation started`, from, shortWait)
	bob.Wait("Console", `network identity of alice \(alice\) updated \(root rotation\)|network identity of alice updated \(root rotation\)`, bobFrom, longWait)
	carol.Wait("Console", `network identity of alice \(alice\) updated \(root rotation\)|network identity of alice updated \(root rotation\)`, carolFrom, longWait)
	newAddr := bob.WaitContact("alice", func(c Contact) bool { return c.NetAddr != oldAddr }, "new address", longWait).NetAddr
	if got := contactOf(t, carol, "alice").NetAddr; got != newAddr {
		t.Errorf("carol has alice at %s, bob at %s", got, newAddr)
	}

	exchange := func(host, member *Instance, text string) {
		t.Helper()
		room := OpenRoom(host, member)
		host.Focus(room)
		host.Send(text)
		if got := member.Wait(room, "^"+host.Name+": "+regexp.QuoteMeta(text)+"$", 0, shortWait); got.Sig != "ok" {
			t.Errorf("%s got %s's message with sig %q", member.Name, host.Name, got.Sig)
		}
		exitRoom(t, member, room)
		exitRoom(t, host, room)
	}
	exchange(alice, bob, "from the new identity")
	exchange(bob, alice, "to the new address")

	alice.Quit()
	alice.Restart()
	exchange(carol, alice, "after the restart")
}
