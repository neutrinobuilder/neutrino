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

package tornode

import (
	"testing"
	"time"
)

func TestIsIPPort(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:9050":   true,
		"[::1]:9050":       true,
		"example.onion:80": false, // host isn't an IP
		"not-an-address":   false,
		"":                 false,
	}
	for in, want := range cases {
		if got := isIPPort(in); got != want {
			t.Errorf("isIPPort(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTorWriterSplitsLines(t *testing.T) {
	ch := make(chan string, 10)
	w := &torWriter{ch: ch}

	if _, err := w.Write([]byte("first line\nsecond line\nthird without newline")); err != nil {
		t.Fatal(err)
	}

	want := []string{"first line", "second line"}
	for i, w := range want {
		if got := <-ch; got != w {
			t.Errorf("line %d: want %q, got %q", i, w, got)
		}
	}
	select {
	case extra := <-ch:
		t.Fatalf("unexpected line sent before the final newline: %q", extra)
	default:
	}

	if _, err := w.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if got := <-ch; got != "third without newline" {
		t.Errorf("third line after the final newline: want 'third without newline', got %q", got)
	}
}

func TestTorWriterSkipsEmptyLines(t *testing.T) {
	ch := make(chan string, 10)
	w := &torWriter{ch: ch}
	if _, err := w.Write([]byte("\n\none line\n\n")); err != nil {
		t.Fatal(err)
	}

	if got := <-ch; got != "one line" {
		t.Errorf("want 'one line', got %q", got)
	}
	select {
	case extra := <-ch:
		t.Fatalf("empty line unexpectedly sent to the log: %q", extra)
	default:
	}
}

func TestTorWriterProgressCallback(t *testing.T) {
	ch := make(chan string, 10)
	var pcts []int
	w := &torWriter{
		ch:         ch,
		onProgress: func(pct int) { pcts = append(pcts, pct) },
	}

	w.Write([]byte("Jul 22 00:00:00.000 [notice] Bootstrapped 42% (loading_descriptors): x\n"))
	<-ch
	if len(pcts) != 1 || pcts[0] != 42 {
		t.Fatalf("onProgress: want [42], got %v", pcts)
	}

	// same percentage repeated: the callback must not be called again (dedup on lastPct).
	w.Write([]byte("Bootstrapped 42% (loading_descriptors): x\n"))
	<-ch
	if len(pcts) != 1 {
		t.Fatalf("onProgress: an unchanged percentage called the callback again: %v", pcts)
	}

	w.Write([]byte("Bootstrapped 100% (done): Done\n"))
	<-ch
	if len(pcts) != 2 || pcts[1] != 100 {
		t.Fatalf("onProgress: want [42 100], got %v", pcts)
	}
}

func TestTorWriterNonBlockingWhenChannelFull(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "fills the buffer"
	w := &torWriter{ch: ch}

	done := make(chan struct{})
	go func() {
		w.Write([]byte("discarded line\n"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write with a full channel blocked instead of silently discarding")
	}
}
