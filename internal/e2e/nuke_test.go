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
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"
)

// decoyName is the decoy identity's username the harness creates for in.
func decoyName(in *Instance) string { return in.Name + "-duress" }

// waitIdentity waits until in's TUI runs as username — across the
// re-entry after a nuke, when the agent socket is recreated.
func waitIdentity(t *testing.T, in *Instance, username string, timeout time.Duration) {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(username) + `:\s`)
	deadline := time.Now().Add(timeout)
	for {
		var r struct {
			Screen string `json:"screen"`
		}
		if err := in.try(map[string]any{"cmd": "screen"}, &r); err == nil && re.MatchString(r.Screen) {
			return
		}
		if in.Exited() {
			t.Fatalf("%s exited instead of running as %s:\n%s", in.Name, username, in.logTail())
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never ran as %s", in.Name, username)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitReentry waits until in's TUI program has ended and the next one
// answers: the agent closes the connection of a program that ends, so a
// request fails once before the new program's socket answers.
func waitReentry(t *testing.T, in *Instance, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ended := false
	for {
		err := in.try(map[string]any{"cmd": "state"}, nil)
		if err != nil {
			ended = true
		} else if ended {
			return
		}
		if in.Exited() {
			t.Fatalf("%s exited instead of starting again:\n%s", in.Name, in.logTail())
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the TUI never started again", in.Name)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// loginFails runs in's binary with its current credentials and expects
// the login to be refused: the process exits without opening its agent
// socket.
func loginFails(t *testing.T, in *Instance) {
	t.Helper()
	_ = os.Remove(in.sockPath())
	cmd := exec.Command(binPath, "--net", "loopback", "agent",
		"--sock", "sock", "--creds", "creds.json", "--loopback-dir", in.run.loopDir)
	cmd.Dir = in.Dir
	cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(in.Dir, "cfg"),
		"HOME="+in.Dir,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shortWait):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("%s: login with the obliterated password still running", in.Name)
	}
	if _, err := os.Stat(in.sockPath()); err == nil {
		t.Fatalf("%s: login with the obliterated password opened the agent socket", in.Name)
	}
}

// TestDuressPassword: /sec-duress refuses an empty password, the real
// identity's password and a mismatched confirmation; once set, logging
// in with it opens the decoy identity, which holds none of the real
// contacts, and the real identity's password no longer opens anything.
func TestDuressPassword(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)
	decoyPwd := "decoy-for-alice"

	from := alice.LineCount("Console")
	alice.Send("/sec-duress")
	enterSecrets(alice, "")
	alice.Wait("Console", `empty password — operation cancelled`, from, shortWait)
	alice.Send("/sec-duress")
	enterSecrets(alice, identityPassword("alice"))
	alice.Wait("Console", `cannot be the same as a real identity's password`, from, shortWait)
	alice.Send("/sec-duress")
	enterSecrets(alice, decoyPwd, "something else")
	alice.Wait("Console", `passwords do not match`, from, shortWait)
	alice.Send("/sec-duress")
	enterSecrets(alice, decoyPwd, decoyPwd)
	alice.Wait("Console", `decoy identity password set`, from, shortWait)

	alice.Quit()
	setIdentityPassword(t, alice, decoyPwd)
	alice.Restart()
	waitIdentity(t, alice, decoyName(alice), shortWait)
	if hasContact(alice, "bob") {
		t.Fatal("the decoy identity shows the real identity's contact bob")
	}

	alice.Quit()
	setIdentityPassword(t, alice, identityPassword("alice"))
	loginFails(t, alice)
}

// TestNukeExpress: /nukex wipes the real identity at once — the process
// keeps running as the decoy identity, which holds none of the real
// contacts; contacts are told the relationship is revoked, a second
// /nukex changes nothing, and the real password no longer logs in while
// the decoy one does.
func TestNukeExpress(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	alice.Send("/nukex")
	waitIdentity(t, alice, decoyName(alice), longWait)
	if hasContact(alice, "bob") {
		t.Fatal("the decoy identity shows the real identity's contact bob after /nukex")
	}
	bob.WaitContact("alice", func(c Contact) bool { return c.RelRevoked }, "relationship revoked", longWait)

	alice.Send("/nukex")
	waitReentry(t, alice, longWait)
	waitIdentity(t, alice, decoyName(alice), shortWait)

	alice.Quit()
	loginFails(t, alice)
	setIdentityPassword(t, alice, identityPassword("alice")+"-duress")
	alice.Restart()
	waitIdentity(t, alice, decoyName(alice), shortWait)
}

// TestNukeTimeout: /sec-nuke-timeout wipes the real identity once the
// interface has stayed locked longer than the threshold; 0 disables it;
// a missing or invalid duration is refused.
func TestNukeTimeout(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")

	from := alice.LineCount("Console")
	alice.Send("/sec-nuke-timeout")
	alice.Wait("Console", `usage: /sec-nuke-timeout <duration\|0>`, from, shortWait)
	alice.Send("/sec-nuke-timeout later")
	alice.Wait("Console", `invalid duration`, from, shortWait)

	alice.Send("/sec-nuke-timeout 0")
	alice.Wait("Console", `automatic time-based nuke disabled`, from, shortWait)
	alice.Send("/sec-lock")
	waitLocked(t, alice, true, shortWait)
	time.Sleep(5 * time.Second)
	unlock(alice, identityPassword("alice"))
	waitLocked(t, alice, false, shortWait)
	waitIdentity(t, alice, "alice", shortWait)

	alice.Send("/sec-nuke-timeout 3s")
	alice.Wait("Console", `time-based nuke threshold set to 3s`, from, shortWait)
	alice.Send("/sec-lock")
	waitIdentity(t, alice, decoyName(alice), longWait)
}

// TestClearAll: /sec-clear-all asks for confirmation — "n" keeps
// everything — and with "y" the process exits and the configuration
// directory (keystore, config, saved QR codes) is gone.
func TestClearAll(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	cfgDir := filepath.Join(alice.Dir, "cfg", "neutrino")

	alice.Send("/sec-clear-all")
	alice.WaitScreen(`Permanently delete keystore, backups and saved QR codes on this device\? Irreversible action\. \[y/n\]`, shortWait)
	alice.Type("n")
	time.Sleep(time.Second)
	if alice.Exited() {
		t.Fatal("process exited after answering n")
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "keystore")); err != nil {
		t.Fatalf("keystore gone after answering n: %v", err)
	}

	alice.Send("/sec-clear-all")
	alice.WaitScreen(`Irreversible action\. \[y/n\]`, shortWait)
	// The process may exit before replying to this keystroke.
	_ = alice.try(map[string]any{"cmd": "type", "text": "y"}, nil)
	deadline := time.Now().Add(shortWait)
	for !alice.Exited() {
		if time.Now().After(deadline) {
			t.Fatal("still running after confirming /sec-clear-all")
		}
		time.Sleep(100 * time.Millisecond)
	}
	entries, err := os.ReadDir(cfgDir)
	if err == nil && len(entries) > 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("configuration directory not wiped: %v", names)
	}
}
