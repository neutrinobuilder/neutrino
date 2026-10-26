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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"neutrino/internal/client"
	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestRoomSlotRejectsSecondDeviceSameIdentity is the end-to-end test for
// "one device per identity per room", unlike the unit tests on
// roomState.ClaimIdentitySlot (rooms_internal_test.go), it exercises the
// FULL real path: two real clients (internal/client.Client), a real server
// (RunOnListener/handleWS), two independent secrets registered for the
// SAME identityPub but different devices (exactly what the invite fan-out
// produces, cmdInvite), verifies that the second device is rejected with
// client.ErrAlreadyConnectedElsewhere while the first is still connected,
// and that it succeeds as soon as that one disconnects.
func TestRoomSlotRejectsSecondDeviceSameIdentity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	registry := serverhs.NewRoomRegistry()
	identityPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devAPub, devAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devBPub, devBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secretA, _ := shared.RandomBytes(32)
	secretB, _ := shared.RandomBytes(32)
	registry.AddSecret("room-1", secretA, "bob", identityPub, []byte("device-A"),
		staticResolver(shared.RelPeerKey{Pub: devAPub}, shared.RelSigningKey{Priv: hostPriv}))
	registry.AddSecret("room-1", secretB, "bob", identityPub, []byte("device-B"),
		staticResolver(shared.RelPeerKey{Pub: devBPub}, shared.RelSigningKey{Priv: hostPriv}))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		// identityPriv/mlkemDecap/knockCh/knownContactPubsFn nil: this test
		// never uses them, exactly like silenced_test.go.
		_ = serverhs.RunOnListener(ctx, ln, registry, nil, nil, nil, nil, serverhs.ServerConfig{})
	}()
	waitServing(t, "http://"+ln.Addr().String()+"/health")

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	cliA := client.New(host, port, "bob", secretA, false, nil, nil, nil,
		shared.RelSigningKey{Priv: devAPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliA.Connect(ctx); err != nil {
		t.Fatalf("device A: Connect: %v", err)
	}

	cliB := client.New(host, port, "bob", secretB, false, nil, nil, nil,
		shared.RelSigningKey{Priv: devBPriv}, shared.RelPeerKey{Pub: hostPub})
	if err := cliB.Connect(ctx); err == nil {
		t.Fatal("device B should have been refused while device A is still connected")
	} else if !errors.Is(err, client.ErrAlreadyConnectedElsewhere) {
		t.Fatalf("want error client.ErrAlreadyConnectedElsewhere, got: %v", err)
	}

	// Device A disconnects (clean close, detected right away by the
	// server's read loop, ws.go, disconnect defer, ReleaseIdentitySlot):
	// device B must now succeed, with no need for any new invite/secret.
	cliA.GracefulClose()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = cliB.Connect(ctx)
		if lastErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("device B should have connected after device A disconnected: %v", lastErr)
	}
}

// TestRoomSlotAllowsSameDeviceReconnect verifies the other branch of
// ClaimIdentitySlot along the real path: the SAME device (same secret, so
// same devicePub) must be able to reconnect freely, never blocked by
// itself, even while its previous session still shows as "connected" from
// the server's point of view (simulating a connection dropped without a
// clean close, e.g. a network timeout).
func TestRoomSlotAllowsSameDeviceReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	registry := serverhs.NewRoomRegistry()
	identityPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := shared.RandomBytes(32)
	registry.AddSecret("room-1", secret, "bob", identityPub, []byte("device-A"),
		staticResolver(shared.RelPeerKey{Pub: devPub}, shared.RelSigningKey{Priv: hostPriv}))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		_ = serverhs.RunOnListener(ctx, ln, registry, nil, nil, nil, nil, serverhs.ServerConfig{})
	}()
	waitServing(t, "http://"+ln.Addr().String()+"/health")

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	newCli := func() *client.Client {
		return client.New(host, port, "bob", secret, false, nil, nil, nil,
			shared.RelSigningKey{Priv: devPriv}, shared.RelPeerKey{Pub: hostPub})
	}

	cli1 := newCli()
	if err := cli1.Connect(ctx); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	// NO explicit disconnection of cli1: from the server's point of view
	// its session still shows as active when cli2 (same device, same
	// secret) attempts its own, it must still succeed (ClaimIdentitySlot:
	// same devicePub → reclaims the slot, evicts the previous session),
	// never a client.ErrAlreadyConnectedElsewhere.
	cli2 := newCli()
	if err := cli2.Connect(ctx); err != nil {
		t.Fatalf("reconnection of the SAME device: want success, got: %v", err)
	}
}
