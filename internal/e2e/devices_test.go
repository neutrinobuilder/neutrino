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
	"testing"
	"time"
)

// TestDeviceLabel: /sec-device-label shows this device's name (the one
// chosen at creation), changes it, and the new name survives a restart.
func TestDeviceLabel(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")

	from := alice.LineCount("Console")
	alice.Send("/sec-device-label")
	alice.Wait("Console", `this device's name: alice-device$`, from, shortWait)
	alice.Send("/sec-device-label laptop")
	alice.Wait("Console", `this device's name set to: laptop$`, from, shortWait)

	alice.Quit()
	alice.Restart()
	from = alice.LineCount("Console")
	alice.Send("/sec-device-label")
	alice.Wait("Console", `this device's name: laptop$`, from, shortWait)
}

// TestDeviceCommandsWithoutSiblings: with no known sibling device,
// /sec-devices, /sec-device-sync and /sec-remote-nuke say an indoor sync
// is needed first.
func TestDeviceCommandsWithoutSiblings(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")

	for _, cmd := range []string{"/sec-devices", "/sec-device-sync", "/sec-device-sync laptop", "/sec-remote-nuke"} {
		from := alice.LineCount("Console")
		alice.Send(cmd)
		alice.Wait("Console", `no known devices — run an indoor sync first \(/sec-indoor-sync\)`, from, shortWait)
	}
}

// indoorSync runs /sec-indoor-sync on two devices of the same identity at
// once and waits until both report it completed.
func indoorSync(t *testing.T, a, b *Instance) {
	t.Helper()
	fromA, fromB := a.LineCount("Console"), b.LineCount("Console")
	a.Send("/sec-indoor-sync")
	b.Send("/sec-indoor-sync")
	for _, in := range []*Instance{a, b} {
		from := fromA
		if in == b {
			from = fromB
		}
		in.Wait("Console", `indoor sync completed: contacts and known devices updated`, from, longWait)
	}
}

// TestIndoorSyncAndDevices: two devices of alice's identity, each with a
// contact the other lacks, meet through /sec-indoor-sync: each gets the
// other's contact, and /sec-devices lists the sibling at once; a second
// sync while one is running is refused.
func TestIndoorSyncAndDevices(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	carol := r.Start("carol")
	Pair(alice, bob)
	alice2 := r.StartSibling(alice, "alice2")
	AddContact(alice2, carol)

	from := alice.LineCount("Console")
	alice.Send("/sec-indoor-sync")
	alice.Send("/sec-indoor-sync")
	alice.Wait("Console", `indoor sync already in progress`, from, shortWait)
	alice2.Send("/sec-indoor-sync")
	alice.Wait("Console", `indoor sync completed`, from, longWait)
	alice2.Wait("Console", `indoor sync completed`, 0, longWait)

	alice.WaitContact("carol", func(Contact) bool { return true }, "synced from alice2", shortWait)
	alice2.WaitContact("bob", func(Contact) bool { return true }, "synced from alice", shortWait)

	alice.Send("/sec-devices")
	alice.WaitScreen(`known devices for this identity:[\s│]+alice2-device[\s│]+- alice`, shortWait)
	alice.Key("esc")
	alice2.Send("/sec-devices")
	alice2.WaitScreen(`known devices for this identity:[\s│]+alice-device[\s│]+- alice`, shortWait)
	alice2.Key("esc")
}

// TestDeviceSync: after an indoor sync, /sec-device-sync sends this
// device's address book to a known sibling over the network — a contact
// added since on one device reaches the other — and refuses a device it
// doesn't know.
func TestDeviceSync(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	dave := r.Start("dave")
	Pair(alice, bob)
	alice2 := r.StartSibling(alice, "alice2")
	indoorSync(t, alice, alice2)

	AddContact(alice, dave)
	from := alice.LineCount("Console")
	from2 := alice2.LineCount("Console")
	alice.Send("/sec-device-sync alice2-device")
	alice.Wait("Console", `contact sync requested from alice2-device`, from, longWait)
	alice2.Wait("Console", `contacts synced from alice`, from2, longWait)
	alice2.WaitContact("dave", func(Contact) bool { return true }, "synced over the network", shortWait)

	alice.Send("/sec-device-sync phone")
	alice.Wait("Console", `specify a known sibling device \(label or DeviceID prefix\): alice2-device`, from, shortWait)
}

// TestRemoteNuke: /sec-remote-nuke picks a known sibling and, once
// confirmed, wipes it remotely: the sibling goes on as the decoy
// identity and confirms the destruction back; "n" cancels.
func TestRemoteNuke(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	alice2 := r.StartSibling(alice, "alice2")
	indoorSync(t, alice, alice2)

	alice.Send("/sec-remote-nuke")
	alice.WaitScreen(`which device do you want to remotely wipe\?`, shortWait)
	alice.Key("enter")
	alice.WaitScreen(`Remotely wipe "alice2-device"\? Irreversible action\. \[y/n\]`, shortWait)
	alice.Type("n")
	time.Sleep(time.Second)
	waitIdentity(t, alice2, "alice", shortWait)

	from := alice.LineCount("Console")
	alice.Send("/sec-remote-nuke")
	alice.Key("enter")
	alice.WaitScreen(`Remotely wipe "alice2-device"\?`, shortWait)
	alice.Type("y")
	alice.Wait("Console", `remote_nuke command for alice2-device sent to 1 address\(es\)`, from, shortWait)
	waitIdentity(t, alice2, decoyName(alice), longWait)
	alice.Wait("Console", `confirmed: target device destroyed`, from, longWait)
}
