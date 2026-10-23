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

package transport

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"
)

// sessionThenDialHandler replies to SESSION CREATE with success and to
// STREAM CONNECT with the outcome given by connectResult — reused by the
// two tests below to drive the dial's outcome without duplicating the
// fakeSAMBridge infrastructure (sam_test.go, same package).
func sessionThenDialHandler(connectResult string) func(rw *bufio.ReadWriter, cmdLine string) {
	return func(rw *bufio.ReadWriter, cmdLine string) {
		switch {
		case strings.HasPrefix(cmdLine, "SESSION CREATE"):
			rw.WriteString("SESSION STATUS RESULT=OK DESTINATION=abc123\n")
			rw.Flush()
		case strings.HasPrefix(cmdLine, "STREAM CONNECT"):
			rw.WriteString("STREAM STATUS RESULT=" + connectResult + "\n")
			rw.Flush()
		}
	}
}

// TestI2PHasCircuitsFalseWithoutSession verifies that with no session
// ever created, HasCircuits is never "healthy".
func TestI2PHasCircuitsFalseWithoutSession(t *testing.T) {
	tr := &i2pTransport{}
	if tr.HasCircuits() {
		t.Fatal("HasCircuits: want false with no SAM session created")
	}
}

// TestI2PHasCircuitsFalseAfterFailedDial verifies that a genuinely
// failed dial (STREAM CONNECT with an outcome other than OK) makes
// HasCircuits() return false — a SAM session existing is not enough by
// itself.
func TestI2PHasCircuitsFalseAfterFailedDial(t *testing.T) {
	b := startFakeSAMBridge(t, sessionThenDialHandler("CANT_REACH_PEER"))
	tr := &i2pTransport{samBridgeAddr: b.addr()}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := tr.DialContext(ctx, "tcp", strings.Repeat("a", 400)); err == nil {
		t.Fatal("DialContext: want an error for a failed STREAM CONNECT")
	}

	if tr.HasCircuits() {
		t.Fatal("HasCircuits: want false after a failed dial, even with an existing SAM session")
	}
}

// TestI2PHasCircuitsRecoversAfterSuccessfulDial verifies the symmetric
// half: after a failed dial has already brought HasCircuits() to false,
// a subsequent successful dial must bring it back to true.
func TestI2PHasCircuitsRecoversAfterSuccessfulDial(t *testing.T) {
	b := startFakeSAMBridge(t, sessionThenDialHandler("OK"))
	tr := &i2pTransport{
		samBridgeAddr:  b.addr(),
		cliSess:        "sess1", // already-existing session
		lastDialFailed: true,    // "unhealthy" state from a previous dial
	}

	if tr.HasCircuits() {
		t.Fatal("precondition: HasCircuits should have been false before the successful dial")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dest := strings.Repeat("a", 400) // > 200 chars: looksLikeI2PDestinationBlob, skips NAMING LOOKUP
	conn, err := tr.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()

	if !tr.HasCircuits() {
		t.Fatal("HasCircuits: want true after a successful dial")
	}
}

// TestI2PDialerForTokenRespectsCtxTimeout verifies that a SAM bridge
// which replies to HELLO but then stays silent on SESSION CREATE doesn't
// leave DialerForToken hanging indefinitely — a ctx with a short timeout
// must unblock it within a reasonable window.
func TestI2PDialerForTokenRespectsCtxTimeout(t *testing.T) {
	silence := make(chan struct{})
	t.Cleanup(func() { close(silence) })
	b := startFakeSAMBridge(t, func(rw *bufio.ReadWriter, cmdLine string) {
		<-silence // never replies to SESSION CREATE
	})
	tr := &i2pTransport{samBridgeAddr: b.addr()}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := tr.DialerForToken(ctx, "file-transfer")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("DialerForToken: want an error for the ctx timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialerForToken didn't unblock within the ctx timeout — session creation ignores ctx")
	}
}
