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

package i2pnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestFreeTCPPort(t *testing.T) {
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("freeTCPPort: port out of range: %d", port)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port %d is not actually free right after: %v", port, err)
	}
	ln.Close()
}

func TestLogWriterSplitsLines(t *testing.T) {
	ch := make(chan string, 10)
	w := &logWriter{ch: ch}
	if _, err := w.Write([]byte("line one\nline two\n")); err != nil {
		t.Fatal(err)
	}

	if got := <-ch; got != "line one" {
		t.Errorf("want 'line one', got %q", got)
	}
	if got := <-ch; got != "line two" {
		t.Errorf("want 'line two', got %q", got)
	}
}

func TestLogWriterNonBlockingWhenChannelFull(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "full"
	w := &logWriter{ch: ch}

	done := make(chan struct{})
	go func() {
		w.Write([]byte("discarded\n"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write with a full channel blocked instead of silently discarding")
	}
}

func TestLogWriterStripsANSIColors(t *testing.T) {
	ch := make(chan string, 10)
	w := &logWriter{ch: ch}
	// Real format observed in i2pd logs (--log=stdout colors
	// unconditionally, unlike Tor): "\x1b[1;36minfo\x1b[0m".
	if _, err := w.Write([]byte("20:06:04@408/\x1b[1;32mnone\x1b[0m - i2pd v2.61.0 starting...\n")); err != nil {
		t.Fatal(err)
	}
	want := "20:06:04@408/none - i2pd v2.61.0 starting..."
	if got := <-ch; got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestLogWriterEvictsOldestWhenFull(t *testing.T) {
	ch := make(chan string, 2)
	w := &logWriter{ch: ch}

	if _, err := w.Write([]byte("one\ntwo\nthree\n")); err != nil {
		t.Fatal(err)
	}

	// The channel has capacity 2: "one" must have been discarded to make
	// room for "three", the most recent line.
	first, second := <-ch, <-ch
	if first != "two" || second != "three" {
		t.Errorf("want [two three] (most recent lines), got [%s %s]", first, second)
	}
}

func TestWaitSAMReadySucceedsWhenListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if err := waitSAMReady(context.Background(), ln.Addr().String(), 2*time.Second, make(chan error)); err != nil {
		t.Fatalf("waitSAMReady: want success, got %v", err)
	}
}

func TestWaitSAMReadyTimesOut(t *testing.T) {
	// a free port with nobody listening: every dial fails until the timeout.
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	start := time.Now()
	if err := waitSAMReady(context.Background(), addr, 300*time.Millisecond, make(chan error)); err == nil {
		t.Fatal("waitSAMReady: want a timeout error, got no error")
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("waitSAMReady: want to wait at least the requested timeout, took %v", elapsed)
	}
}

func TestWaitSAMReadyRespectsContextCancellation(t *testing.T) {
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitSAMReady(ctx, addr, 5*time.Second, make(chan error)); err == nil {
		t.Fatal("waitSAMReady: want an error for an already-cancelled context")
	}

}

func TestWaitSAMReadyReturnsErrorWhenProcessExits(t *testing.T) {
	port, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	exited := make(chan error, 1)
	exited <- errors.New("exit status 1")

	start := time.Now()
	err = waitSAMReady(context.Background(), addr, 5*time.Second, exited)
	if err == nil {
		t.Fatal("waitSAMReady: want an error for an exited process, got no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waitSAMReady: want an immediate return when the process exits, took %v", elapsed)
	}
}
