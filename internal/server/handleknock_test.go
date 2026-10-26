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
	"crypto/mlkem"
	"crypto/rand"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestHandleKnockMutualityFilter covers the pre-decryption filter via
// shared.KnockDHTag: a knock from an unknown sender must be discarded
// WITHOUT being routed to knockCh, with the SAME HTTP response (202) as a
// processed knock, a knock from a known contact, or from the recipient
// itself (self-probe), must instead arrive on knockCh.
func TestHandleKnockMutualityFilter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey server: %v", err)
	}
	knownPub, knownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey known: %v", err)
	}
	strangerPub, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey stranger: %v", err)
	}

	registry := serverhs.NewRoomRegistry()
	knockCh := make(chan shared.KnockPayload, 4)
	knownContacts := func() [][]byte { return [][]byte{knownPub} }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		_ = serverhs.RunOnListener(ctx, ln, registry, serverPriv, nil, knockCh,
			knownContacts, serverhs.ServerConfig{})
	}()

	url := "http://" + ln.Addr().String() + "/knock"

	post := func(t *testing.T, senderPriv ed25519.PrivateKey, kp shared.KnockPayload) *http.Response {
		t.Helper()
		tag, err := shared.KnockDHTag(senderPriv, serverPub)
		if err != nil {
			t.Fatalf("KnockDHTag: %v", err)
		}
		body, err := shared.EncryptKnockWithTag(serverPub, nil, kp, tag)
		if err != nil {
			t.Fatalf("EncryptKnockWithTag: %v", err)
		}
		resp, err := http.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("Post: %v", err)
		}
		return resp
	}

	t.Run("known contact: forwarded", func(t *testing.T) {
		resp := post(t, knownPriv, shared.KnockPayload{FromUsername: "known", FromIdentityPub: knownPub})
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		select {
		case p := <-knockCh:
			if p.FromUsername != "known" {
				t.Errorf("FromUsername = %q, want known", p.FromUsername)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("knock from a known contact not routed to knockCh")
		}
	})

	t.Run("unknown sender: discarded, same 202, never forwarded", func(t *testing.T) {
		resp := post(t, strangerPriv, shared.KnockPayload{FromUsername: "stranger", FromIdentityPub: strangerPub})
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (same response as a processed knock, must not be distinguishable)", resp.StatusCode)
		}
		select {
		case p := <-knockCh:
			t.Fatalf("knock from an unknown sender routed to knockCh: %+v", p)
		case <-time.After(300 * time.Millisecond):
		}
	})

	t.Run("self-probe: forwarded", func(t *testing.T) {
		resp := post(t, serverPriv, shared.KnockPayload{Type: "self_probe", FromUsername: "self", FromIdentityPub: serverPub})
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		select {
		case p := <-knockCh:
			if p.Type != "self_probe" {
				t.Errorf("Type = %q, want self_probe", p.Type)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("self-probe not routed to knockCh")
		}
	})

	t.Run("malformed body: bad request", func(t *testing.T) {
		resp, err := http.Post(url, "application/json", strings.NewReader("not json"))
		if err != nil {
			t.Fatalf("Post: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// TestHandleKnockHybridDecryption mirrors the "known contact: forwarded"
// case above but encrypts the knock in hybrid X25519+ML-KEM-768 form,
// verifies that handleKnock, with a non-nil mlkemDecap (RunOnListener),
// decrypts it correctly and routes it to knockCh exactly like a classic
// knock.
func TestHandleKnockHybridDecryption(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey server: %v", err)
	}
	serverMLKEM, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	knownPub, knownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey known: %v", err)
	}

	registry := serverhs.NewRoomRegistry()
	knockCh := make(chan shared.KnockPayload, 4)
	knownContacts := func() [][]byte { return [][]byte{knownPub} }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		_ = serverhs.RunOnListener(ctx, ln, registry, serverPriv, serverMLKEM, knockCh,
			knownContacts, serverhs.ServerConfig{})
	}()

	url := "http://" + ln.Addr().String() + "/knock"
	tag, err := shared.KnockDHTag(knownPriv, serverPub)
	if err != nil {
		t.Fatalf("KnockDHTag: %v", err)
	}
	body, err := shared.EncryptKnockWithTag(serverPub, serverMLKEM.EncapsulationKey(), shared.KnockPayload{
		FromUsername:    "known",
		FromIdentityPub: knownPub,
	}, tag)
	if err != nil {
		t.Fatalf("EncryptKnockWithTag: %v", err)
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	select {
	case p := <-knockCh:
		if p.FromUsername != "known" {
			t.Errorf("FromUsername = %q, want known", p.FromUsername)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hybrid knock not routed to knockCh")
	}
}
