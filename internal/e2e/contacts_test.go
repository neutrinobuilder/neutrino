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
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// contactOf returns in's address-book entry for username, failing if
// absent.
func contactOf(t *testing.T, in *Instance, username string) Contact {
	t.Helper()
	for _, c := range in.Contacts() {
		if c.Username == username {
			return c
		}
	}
	t.Fatalf("%s: no contact %s", in.Name, username)
	return Contact{}
}

// hasContact reports whether in's address book holds username.
func hasContact(in *Instance, username string) bool {
	for _, c := range in.Contacts() {
		if c.Username == username {
			return true
		}
	}
	return false
}

// uriPattern matches the start of in's identity URI (scheme, username
// and the start of the public key) after a popup's "uri:" label, which
// may wrap it onto the next line, inside the popup border.
func uriPattern(in *Instance) string {
	uri := in.URI()
	return `uri:[\s│]+` + regexp.QuoteMeta(uri[:len("nu://"+in.Name+"/")+16])
}

// TestContactInfo: /cnt-info shows a contact's URI, network address and
// local data — by name, through the picker, and for oneself ("self").
func TestContactInfo(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	addr := contactOf(t, alice, "bob").NetAddr

	alice.Send("/cnt-info bob")
	alice.WaitScreen(`▸ bob \(bob\)`, shortWait)
	alice.WaitScreen(uriPattern(bob), shortWait)
	alice.WaitScreen(`addr:\s+`+regexp.QuoteMeta(addr), shortWait)
	alice.Key("esc")

	alice.Send("/cnt-info")
	alice.Type("bob")
	alice.Key("enter")
	alice.WaitScreen(`▸ bob \(bob\)`, shortWait)
	alice.Key("esc")

	alice.Send("/cnt-info self")
	alice.WaitScreen(`▸ alice \(you\)`, shortWait)
	alice.WaitScreen(uriPattern(alice), shortWait)
	alice.Key("esc")
}

// TestContactEditLocalName: /cnt-edit changes a local name (the username
// by default, as /cnt-add proposes), which then resolves the contact in
// other commands and survives a restart; an empty name removes it.
func TestContactEditLocalName(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	from := alice.LineCount("Console")
	alice.Send("/cnt-edit bob")
	alice.WaitScreen(`Local name for bob \[bob, empty = remove\]`, shortWait)
	alice.Type("Roberto")
	alice.Key("enter")
	alice.Wait("Console", `local name for bob: Roberto`, from, shortWait)
	if got := contactOf(t, alice, "bob").LocalName; got != "Roberto" {
		t.Fatalf("local name = %q, want Roberto", got)
	}

	alice.Send("/cnt-info Roberto")
	alice.WaitScreen(`local name: Roberto`, shortWait)
	alice.Key("esc")

	alice.Quit()
	alice.Restart()
	if got := contactOf(t, alice, "bob").LocalName; got != "Roberto" {
		t.Fatalf("local name after restart = %q, want Roberto", got)
	}

	from = alice.LineCount("Console")
	alice.Send("/cnt-edit")
	alice.Type("Rob")
	alice.Key("enter")
	alice.WaitScreen(`Local name for bob \[Roberto, empty = remove\]`, shortWait)
	alice.Key("enter")
	alice.Wait("Console", `local name for bob removed`, from, shortWait)
	if got := contactOf(t, alice, "bob").LocalName; got != "" {
		t.Errorf("local name after removal = %q, want empty", got)
	}
}

// TestContactDelete: /cnt-del removes a contact for good (also after a
// restart) and first removes them from every room we host; the picker
// form works as well.
func TestContactDelete(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob)

	from := alice.LineCount("Console")
	roomFrom := alice.LineCount(room)
	alice.Send("/cnt-del bob")
	alice.Wait(room, `bob \(bob\) was removed from the room`, roomFrom, shortWait)
	alice.Wait("Console", `contact removed: bob`, from, shortWait)
	alice.WaitUsers(room, []string{"alice"}, longWait)
	if hasContact(alice, "bob") {
		t.Fatal("bob still in the address book after /cnt-del")
	}

	from = alice.LineCount("Console")
	alice.Send("/cnt-del")
	alice.Type("carol")
	alice.Key("enter")
	alice.Wait("Console", `contact removed: carol`, from, shortWait)

	alice.Quit()
	alice.Restart()
	for _, name := range []string{"bob", "carol"} {
		if hasContact(alice, name) {
			t.Errorf("%s back in the address book after a restart", name)
		}
	}
}

// TestContactCardIgnore: a received contact card discarded with
// /cnt-ignore is gone — /cnt-save no longer finds it and the contact is
// never added.
func TestContactCardIgnore(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	Pair(alice, carol)
	room := OpenRoom(alice, bob)

	offerContactCard(t, alice, bob, room, "carol")
	bob.Focus(room)
	roomFrom := bob.LineCount(room)
	bob.Send("/cnt-ignore")
	bob.Wait(room, `contact card discarded`, roomFrom, shortWait)

	from := bob.LineCount("Console")
	bob.Send("/cnt-save")
	bob.Wait("Console", `no pending contact card`, from, shortWait)
	if hasContact(bob, "carol") {
		t.Error("carol added although her card was discarded")
	}
}

// runActive runs /active until its summary matching want appears in the
// Console — a periodic probe already in flight makes /active answer
// "probe already in progress" instead, so it is retried.
func runActive(t *testing.T, in *Instance, want string) {
	t.Helper()
	deadline := time.Now().Add(longWait)
	for {
		from := in.LineCount("Console")
		in.Send("/active")
		probeEnd := time.Now().Add(shortWait)
		for time.Now().Before(probeEnd) {
			for _, l := range in.Lines("Console", from) {
				if regexp.MustCompile(want).MatchString(l.Text) {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: /active never reported %q", in.Name, want)
		}
	}
}

// TestActiveProbe: /active reports a reachable contact as online and,
// once its process is gone, as unreachable.
func TestActiveProbe(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	runActive(t, alice, `online: bob`)
	bob.Kill()
	runActive(t, alice, `unreachable: bob`)
}

// TestShowQRAndReadQRCode: bob saves his identity QR with /show-qr
// (multi-part PNGs), alice reads those files with /cnt-read-qrcode and
// adds him, and the two then talk in a room. The animated /show-qr
// popup shows bob's own URI. Reading from the camera needs a device and
// isn't covered here.
func TestShowQRAndReadQRCode(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")

	bob.Send("/show-qr")
	bob.Key("down")
	bob.Key("enter")
	bob.WaitScreen(`▸ bob \(you\)`, shortWait)
	bob.WaitScreen(uriPattern(bob), shortWait)
	bob.Key("esc")

	cfgDir := filepath.Join(bob.Dir, "cfg", "neutrino")
	for _, old := range globParts(t, cfgDir) {
		os.Remove(old)
	}
	bob.Send("/show-qr")
	bob.Key("enter")
	bob.WaitScreen(`Identity QR saved to:`, shortWait)
	bob.Key("esc")
	parts := globParts(t, cfgDir)
	if len(parts) == 0 {
		t.Fatal("/show-qr saved no PNG part")
	}
	for _, p := range parts {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(alice.Dir, filepath.Base(p)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	from := alice.LineCount("Console")
	alice.Send("/cnt-read-qrcode")
	alice.WaitScreen(`Read QR from:`, shortWait)
	alice.Type("f")
	alice.Type("identity-qr-bob-part")
	for i := range parts {
		if i > 0 {
			alice.Key("down")
		}
		alice.Key("space")
	}
	alice.Key("enter")
	alice.WaitScreen(`Save this contact\? \[Y/n\]`, shortWait)
	alice.Key("enter")
	alice.WaitScreen(`Local name \[default: bob\]`, shortWait)
	alice.Key("enter")
	alice.Wait("Console", `contact added: bob`, from, shortWait)

	AddContact(bob, alice)
	alice.WaitReady("bob")
	bob.WaitReady("alice")
	room := OpenRoom(alice, bob)
	alice.Focus(room)
	alice.Send("added from your QR")
	got := bob.Wait(room, "^alice: added from your QR$", 0, shortWait)
	if got.Sig != "ok" {
		t.Errorf("bob received alice's message with sig %q, want ok", got.Sig)
	}
}

// globParts returns the identity QR's PNG parts in dir, in part order.
func globParts(t *testing.T, dir string) []string {
	t.Helper()
	parts, err := filepath.Glob(filepath.Join(dir, "identity-qr-*-part*.png"))
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

// TestRelInitOneSidedAdd: alice adds bob before bob adds alice, so her
// rel_init is dropped by bob's mutuality filter. Once bob adds alice the
// exchange completes on both sides right away, never waiting for alice's
// next probe cycle (set here far beyond the wait).
func TestRelInitOneSidedAdd(t *testing.T) {
	r := NewRun(t)
	r.Config = maps.Clone(FastTimers)
	r.Config["active_interval"] = "10m"
	r.Config["active_initial_delay"] = "10m"
	alice := r.Start("alice")
	bob := r.Start("bob")

	AddContact(alice, bob)
	time.Sleep(2 * time.Second)
	if contactOf(t, alice, "bob").ReadyDevices > 0 {
		t.Fatal("bob ready for alice before bob added alice")
	}
	AddContact(bob, alice)
	bob.WaitContact("alice", func(c Contact) bool { return c.ReadyDevices > 0 }, "ready", shortWait)
	alice.WaitContact("bob", func(c Contact) bool { return c.ReadyDevices > 0 }, "ready", shortWait)
}
