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

package server_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	serverhs "neutrino/internal/server"
)

// TestRunOnListenerSilencedRejectsConnections covers the application-level
// silencing of the old hidden service after a rotation: with
// ServerConfig.Silenced returning true, EVERY entry point (WS, /health,
// /knock) must close the connection immediately, without completing any
// protocol, verified here on WS and /health, the two most representative
// paths (handshake vs. plain HTTP response). The listener/onion service
// itself is never closed by this mechanism, only the application above it
// stops responding.
func TestRunOnListenerSilencedRejectsConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	registry := serverhs.NewRoomRegistry()
	registry.AddSecret("room-1", []byte("shared-secret-silenced-test"), "", nil, nil, nil)

	silenced := true
	cfg := serverhs.ServerConfig{Silenced: func() bool { return silenced }}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		// identityPriv/mlkemDecap/knockCh/knownContactPubsFn nil: this test
		// must never reach the point of using them, which is exactly what
		// it verifies.
		_ = serverhs.RunOnListener(ctx, ln, registry, nil, nil, nil, nil, cfg)
	}()

	baseURL := "http://" + ln.Addr().String()
	wsURL := "ws://" + ln.Addr().String() + "/ws/chat"

	// /health must respond 404, not the normal JSON status.
	waitServing(t, baseURL+"/health")
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/health silenced: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	// The WS dial must never complete the upgrade.
	if conn, _, err := websocket.Dial(ctx, wsURL, nil); err == nil {
		conn.CloseNow()
		t.Fatal("websocket.Dial: want a failure with Silenced=true, upgrade succeeded")
	}

	// With silencing turned off, the same listener goes back to responding
	// normally, confirms that the listener/onion service itself was never
	// touched, only the application policy.
	silenced = false
	resp2, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health after unsilence: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("/health after unsilence: status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
}

func waitServing(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server didn't start answering within the timeout: %s", url)
}
