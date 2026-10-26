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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitLocked waits until in's interface lock state is want.
func waitLocked(t *testing.T, in *Instance, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for in.State().Locked != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: interface locked = %v, want %v", in.Name, !want, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unlock types secret on the lock screen and presses Enter.
func unlock(in *Instance, secret string) {
	in.t.Helper()
	in.Type(secret)
	in.Key("enter")
}

// enterSecrets answers a sequence of masked prompts.
func enterSecrets(in *Instance, secrets ...string) {
	in.t.Helper()
	for _, s := range secrets {
		if s != "" {
			in.Type(s)
		}
		in.Key("enter")
	}
}

// identityPassword is the identity password the harness gives name.
func identityPassword(name string) string { return "pi-" + name }

// TestInterfaceLock: /sec-lock locks the interface while rooms keep
// receiving; a wrong secret is refused, the identity password unlocks.
// A PIN set with /sec-lock-pin unlocks too, the identity password still
// does, and invalid PINs are refused.
func TestInterfaceLock(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	room := OpenRoom(alice, bob)
	bob.Focus(room)

	alice.Send("/sec-lock")
	waitLocked(t, alice, true, shortWait)
	alice.WaitScreen(`Interface locked\. Secret:`, shortWait)
	bob.Send("while you were away")
	alice.Wait(room, "^bob: while you were away$", 0, shortWait)

	unlock(alice, "wrong")
	alice.WaitScreen(`wrong secret`, shortWait)
	if !alice.State().Locked {
		t.Fatal("a wrong secret unlocked the interface")
	}
	unlock(alice, identityPassword("alice"))
	waitLocked(t, alice, false, shortWait)

	from := alice.LineCount("Console")
	alice.Send("/sec-lock-pin")
	enterSecrets(alice, "12a4")
	alice.Wait("Console", `the PIN must contain digits only`, from, shortWait)
	alice.Send("/sec-lock-pin")
	enterSecrets(alice, "123")
	alice.Wait("Console", `the PIN must be at least 4 digits`, from, shortWait)
	alice.Send("/sec-lock-pin")
	enterSecrets(alice, "1234", "4321")
	alice.Wait("Console", `passwords do not match`, from, shortWait)
	alice.Send("/sec-lock-pin")
	enterSecrets(alice, "1234", "1234", "9", "0")
	alice.Wait("Console", `interface lock secret set`, from, shortWait)

	alice.Send("/sec-lock")
	waitLocked(t, alice, true, shortWait)
	unlock(alice, "1234")
	waitLocked(t, alice, false, shortWait)
	alice.Send("/sec-lock")
	waitLocked(t, alice, true, shortWait)
	unlock(alice, identityPassword("alice"))
	waitLocked(t, alice, false, shortWait)
}

// TestInterfaceLockTimeout: /sec-lock-timeout locks the interface after
// the given inactivity; 0 disables it; invalid or missing durations are
// refused.
func TestInterfaceLockTimeout(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")

	from := alice.LineCount("Console")
	alice.Send("/sec-lock-timeout")
	alice.Wait("Console", `usage: /sec-lock-timeout <duration\|0>`, from, shortWait)
	alice.Send("/sec-lock-timeout soon")
	alice.Wait("Console", `invalid duration`, from, shortWait)

	alice.Send("/sec-lock-timeout 2s")
	alice.Wait("Console", `lock inactivity threshold set to 2s`, from, shortWait)
	waitLocked(t, alice, true, shortWait)
	unlock(alice, identityPassword("alice"))
	waitLocked(t, alice, false, shortWait)

	alice.Send("/sec-lock-timeout 0")
	alice.Wait("Console", `automatic lock disabled`, from, shortWait)
	time.Sleep(5 * time.Second)
	if alice.State().Locked {
		t.Fatal("interface locked after the automatic lock was disabled")
	}
}

// TestPasswordChangeAndBackup: /sec-backup shows the 24 words only after
// the identity password; /sec-passwd refuses a wrong current password
// and mismatched confirmations, and after a change the new password,
// not the old one, opens the backup, unlocks the interface and logs in
// after a restart.
func TestPasswordChangeAndBackup(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	oldPwd, newPwd := identityPassword("alice"), "pi-alice-new"

	from := alice.LineCount("Console")
	alice.Send("/sec-backup")
	enterSecrets(alice, "wrong")
	alice.Wait("Console", `wrong password, backup cancelled`, from, shortWait)
	alice.Send("/sec-backup")
	enterSecrets(alice, oldPwd)
	alice.WaitScreen(`IDENTITY BACKUP, 24 BIP-39 WORDS`, shortWait)
	alice.Key("esc")

	alice.Send("/sec-passwd")
	enterSecrets(alice, "wrong", newPwd, newPwd)
	alice.Wait("Console", `password change: current password is incorrect`, from, shortWait)
	alice.Send("/sec-passwd")
	enterSecrets(alice, oldPwd, newPwd, "different")
	alice.Wait("Console", `passwords do not match`, from, shortWait)
	alice.Send("/sec-passwd")
	enterSecrets(alice, oldPwd, newPwd, newPwd)
	alice.Wait("Console", `identity password updated`, from, shortWait)

	from = alice.LineCount("Console")
	alice.Send("/sec-backup")
	enterSecrets(alice, oldPwd)
	alice.Wait("Console", `wrong password, backup cancelled`, from, shortWait)
	alice.Send("/sec-backup")
	enterSecrets(alice, newPwd)
	alice.WaitScreen(`IDENTITY BACKUP, 24 BIP-39 WORDS`, shortWait)
	alice.Key("esc")

	alice.Send("/sec-lock")
	waitLocked(t, alice, true, shortWait)
	unlock(alice, oldPwd)
	alice.WaitScreen(`wrong secret`, shortWait)
	unlock(alice, newPwd)
	waitLocked(t, alice, false, shortWait)

	alice.Quit()
	setIdentityPassword(t, alice, newPwd)
	alice.Restart()
	if !hasContact(alice, "bob") {
		t.Fatal("bob missing after logging in with the new password")
	}
	room := OpenRoom(alice, bob)
	alice.Focus(room)
	alice.Send("after the password change")
	bob.Wait(room, "^alice: after the password change$", 0, shortWait)
}

// setIdentityPassword rewrites in's credentials file with a new
// identity password, used by the next Restart.
func setIdentityPassword(t *testing.T, in *Instance, pwd string) {
	t.Helper()
	path := filepath.Join(in.Dir, "creds.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var creds map[string]any
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatal(err)
	}
	creds["password_identity"] = pwd
	if data, err = json.Marshal(creds); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
