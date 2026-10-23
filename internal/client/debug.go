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

package client

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Dbg has two independent, simultaneous destinations: displayCh (the
// on-screen echo — the TUI's Console tab, toggleable at any time with
// SetDebug) and fileCh (the file
// opened by `neutrino debug <file>` via SetDebugFile). Each lives on
// its own: SetDebug(nil) only turns off the on-screen echo, never the
// file; the only way to stop the file is calling the stop() returned by
// SetDebugFile.
var (
	debugMu   sync.Mutex
	displayCh chan<- string
	fileCh    chan<- string
)

// SetDebug enables (ch != nil) or disables (ch == nil) debug's
// on-screen echo. Called by the TUI with m.debugLogCh when /debug on|off
// runs. Has no effect on
// a file opened with SetDebugFile: the two sinks are independent.
func SetDebug(ch chan<- string) {
	debugMu.Lock()
	displayCh = ch
	debugMu.Unlock()
}

// SetDebugFile enables debug output by writing every line (timestamped)
// directly to a file — used by `neutrino debug <file>`. Independent of
// SetDebug/displayCh: no /debug on|off in the TUI, at any point in the
// session, stops this writing. Unlike the Console tab, which lives only
// in RAM and disappears with the process, the file stays on disk even
// if the process dies in a crash (SIGSYS etc.), useful specifically for
// capturing what happens right before a crash that leaves no other
// output. Returns a function to call before exiting to cleanly close
// the channel and file.
func SetDebugFile(path string) (stop func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	ch := make(chan string, 2000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range ch {
			fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), line)
		}
	}()
	debugMu.Lock()
	fileCh = ch
	debugMu.Unlock()
	return func() {
		debugMu.Lock()
		fileCh = nil
		debugMu.Unlock()
		close(ch)
		<-done // waits for the goroutine to write out every already-queued line
		f.Close()
	}, nil
}

// Dbg emits a debug message to every active sink (on-screen echo, file,
// both, or neither — independent of each other).
// Thread-safe: can be called from any goroutine.
// Uses a non-blocking select for each sink: the message is dropped on
// that sink if its buffer is full, never blocking.
// Exported (not just for use inside this package) because it's also
// called from the tui package, which holds the desktop TUI separate
// from client.go.
func Dbg(format string, args ...any) {
	debugMu.Lock()
	dch, fch := displayCh, fileCh
	debugMu.Unlock()
	if dch == nil && fch == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if dch != nil {
		select {
		case dch <- msg:
		default:
		}
	}
	if fch != nil {
		select {
		case fch <- msg:
		default:
		}
	}
}

// ShortUID returns a UUID's first 8 characters for logs. Exported for
// the same reason as Dbg (also called from the tui package).
func ShortUID(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}
