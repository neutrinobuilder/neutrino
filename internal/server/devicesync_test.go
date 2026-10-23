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
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"neutrino/internal/client"
	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestDeviceSyncEndpoint covers POST /device-sync: a knock from this same
// identity is accepted even when far larger than POST /knock allows (a
// whole address book), while a foreign tag is dropped with the usual 202
// before the body is ever read and a large knock to POST /knock stays
// refused.
func TestDeviceSyncEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	knockCh := make(chan shared.KnockPayload, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		_ = serverhs.RunOnListener(ctx, ln, serverhs.NewRoomRegistry(), serverPriv, nil, knockCh,
			func() [][]byte { return nil }, serverhs.ServerConfig{})
	}()
	addr := ln.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	// Well beyond POST /knock's 26000-byte limit.
	big := make([]byte, 100_000)
	rand.Read(big)
	kp := shared.KnockPayload{
		Type: "device_sync", FromUsername: "alice", FromIdentityPub: serverPub,
		DeviceSync: &shared.DeviceSyncPayload{SyncData: big},
	}
	envelope := func(priv ed25519.PrivateKey) string {
		tag, err := shared.KnockDHTag(priv, serverPub)
		if err != nil {
			t.Fatal(err)
		}
		env, err := shared.EncryptKnockWithTag(serverPub, nil, kp, tag)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}

	if err := client.PostDeviceSync(ctx, dial, "peer", envelope(serverPriv), 5*time.Second); err != nil {
		t.Fatalf("own identity's device_sync refused: %v", err)
	}
	select {
	case p := <-knockCh:
		if p.Type != "device_sync" || len(p.DeviceSync.SyncData) != len(big) {
			t.Fatalf("delivered %q with %d bytes of sync data", p.Type, len(p.DeviceSync.SyncData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device_sync never delivered")
	}

	// A foreign tag: same 202, nothing delivered.
	if err := client.PostDeviceSync(ctx, dial, "peer", envelope(strangerPriv), 5*time.Second); err != nil {
		t.Fatalf("foreign tag answered differently from an accepted one: %v", err)
	}
	select {
	case p := <-knockCh:
		t.Fatalf("knock with a foreign tag delivered: %q", p.Type)
	case <-time.After(300 * time.Millisecond):
	}

	// A header tag that doesn't match the envelope's own is refused.
	env := envelope(serverPriv)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+shared.DeviceSyncPath, strings.NewReader(env))
	otherTag, _ := shared.KnockDHTag(serverPriv, serverPub)
	otherTag[0] ^= 0xff
	req.Header.Set(shared.DeviceSyncTagHeader, base64.StdEncoding.EncodeToString(otherTag))
	if resp, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("mismatched header tag: status %d, want the same 202 as any foreign tag", resp.StatusCode)
	}

	// The same large knock to POST /knock stays refused.
	resp, err := http.Post("http://"+addr+"/knock", "application/json", strings.NewReader(env))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("large knock to /knock: status %d, want 400", resp.StatusCode)
	}
}
