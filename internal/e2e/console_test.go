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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"neutrino/internal/client"
	"neutrino/internal/version"
)

// TestHelpAndInfoApp: /help lists the commands in a popup and /info-app
// shows the running version; a stray argument is refused.
func TestHelpAndInfoApp(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")

	total := len(client.CommandList())
	alice.Send("/help")
	alice.WaitScreen(`── Available commands ──`, shortWait)
	alice.WaitScreen(fmt.Sprintf(`1–15 / %d`, total), shortWait)
	alice.Key("pgdown")
	alice.WaitScreen(fmt.Sprintf(`16–30 / %d`, total), shortWait)
	alice.WaitScreen(`/grp-invite`, shortWait)
	alice.Key("esc")

	alice.Send("/info-app")
	alice.WaitScreen(`Version: `+regexp.QuoteMeta(version.Full()), shortWait)
	alice.Key("esc")

	from := alice.LineCount("Console")
	alice.Send("/info-app now")
	alice.Wait("Console", `/info-app takes no arguments`, from, shortWait)
}

// screenCount counts the lines of in's screen containing text.
func screenCount(in *Instance, text string) int {
	return strings.Count(in.Screen(), text)
}

// TestCompactAndConsoleExport: /compact on hides repeated consecutive
// Console lines on screen and in /console-export, /compact off shows
// them again; /compact works only in Console and refuses other
// arguments.
func TestCompactAndConsoleExport(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	// The periodic probe writes the same line every few seconds.
	deadline := time.Now().Add(longWait)
	for screenCount(alice, "Probe activation") < 3 {
		if time.Now().After(deadline) {
			t.Fatal("never saw three repeated probe lines")
		}
		time.Sleep(500 * time.Millisecond)
	}

	from := alice.LineCount("Console")
	alice.Send("/compact")
	alice.Wait("Console", `compaction off — use /compact on or /compact off`, from, shortWait)
	alice.Send("/compact on")
	alice.Wait("Console", `compaction on`, from, shortWait)
	compacted := screenCount(alice, "Probe activation")

	exportConsole(t, alice)
	data := readExport(t, alice)
	if !strings.Contains(data, " • contact added: bob") {
		t.Errorf("console export lacks the contact line:\n%s", data)
	}
	if prev, line := repeatedLine(data); line != "" {
		t.Errorf("compacted export repeats %q right after %q", line, prev)
	}

	alice.Send("/compact off")
	alice.Wait("Console", `compaction off`, from, shortWait)
	if n := screenCount(alice, "Probe activation"); n <= compacted {
		t.Errorf("%d probe lines on screen with compaction off, %d with it on: want more back", n, compacted)
	}

	from = alice.LineCount("Console")
	alice.Send("/compact maybe")
	alice.Wait("Console", `usage: /compact on \| /compact off`, from, shortWait)
	alice.Focus("Contacts")
	alice.Send("/compact on")
	alice.Wait("Console", `/compact only available from the console tab`, from, shortWait)
}

// repeatedLine returns the first pair of consecutive export lines with
// the same content once the timestamp is stripped, or empty strings.
func repeatedLine(data string) (string, string) {
	content := func(l string) string {
		if _, rest, ok := strings.Cut(l, " • "); ok {
			return rest
		}
		return l
	}
	lines := strings.Split(strings.TrimSpace(data), "\n")
	for i := 1; i < len(lines); i++ {
		if content(lines[i]) == content(lines[i-1]) {
			return lines[i-1], lines[i]
		}
	}
	return "", ""
}

// exportConsole runs /console-export and accepts the proposed name and
// folder (the instance directory).
func exportConsole(t *testing.T, in *Instance) {
	t.Helper()
	os.Remove(exportPath(in))
	in.Send("/console-export")
	in.WaitScreen(`console export file name — editable`, shortWait)
	in.Key("enter")
	in.WaitScreen(`save "console-`+in.Name+`\.txt" in — `, shortWait)
	in.Key("enter")
}

func exportPath(in *Instance) string {
	return filepath.Join(in.Dir, "console-"+in.Name+".txt")
}

// readExport waits for the console export file and returns its content.
func readExport(t *testing.T, in *Instance) string {
	t.Helper()
	deadline := time.Now().Add(shortWait)
	for {
		if data, err := os.ReadFile(exportPath(in)); err == nil && len(data) > 0 {
			return string(data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: console export never written", in.Name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDebugToggle: /debug on echoes internal debug lines into Console,
// /debug off stops them; the status form and a wrong argument behave.
func TestDebugToggle(t *testing.T) {
	r := NewRun(t)
	alice := r.Start("alice")
	bob := r.Start("bob")
	Pair(alice, bob)

	from := alice.LineCount("Console")
	alice.Send("/debug")
	alice.Wait("Console", `debug off — use /debug on or /debug off`, from, shortWait)
	alice.Send("/debug loud")
	alice.Wait("Console", `usage: /debug on \| /debug off`, from, shortWait)

	alice.Send("/debug on")
	on := alice.Wait("Console", `debug active`, from, shortWait)
	alice.Wait("Console", `^\[dbg\] `, on.N, longWait)

	alice.Send("/debug off")
	off := alice.Wait("Console", `^▸ debug off$`, on.N, shortWait)
	time.Sleep(12 * time.Second)
	for _, l := range alice.Lines("Console", off.N+1) {
		if strings.HasPrefix(l.Text, "[dbg] ") {
			t.Fatalf("debug line after /debug off: %q", l.Text)
		}
	}
}
