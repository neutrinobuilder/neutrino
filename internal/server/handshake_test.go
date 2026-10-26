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
	"bytes"
	"context"
	"crypto/mlkem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	clienths "neutrino/internal/client"
	serverhs "neutrino/internal/server"
	"neutrino/internal/shared"
)

// TestHandshakeE2ENoRelKeyRejected verifies that the server always rejects
// a client whose IdentityKey-per-relationship is unknown to whoever
// distributed the secret (zero-value peerKey, no residual permissive
// policy).
func TestHandshakeE2ENoRelKeyRejected(t *testing.T) {
	secret := []byte("shared-secret-handshake-e2e-test-256bit")

	type result struct {
		res shared.HandshakeResult
		err error
	}
	srvCh := make(chan result, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		defer conn.CloseNow()
		lookup := func(nonceClient, proof []byte) ([]byte, string, string, []byte, []byte, shared.RelPeerKey, shared.RelSigningKey, bool) {
			if _, ok := shared.VerifyRoomProof(secret, nonceClient, proof); ok {
				return secret, "test-room", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, true
			}
			return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		res, err := serverhs.DoServerHandshake(r.Context(), conn, lookup, nil)
		srvCh <- result{res, err}
	}))
	defer srv.Close()

	// client
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	// The client sends ClientHello anyway (no IdentityKey-per-relationship,
	// zero-value mySigningKey), the server must close the connection
	// because the peerKey known from the bootstrap is empty, so we expect
	// an error both client-side (recv server hello failed, connection
	// closed) and server-side (explicit reject).
	_, cliErr := clienths.DoClientHandshake(
		context.Background(), conn,
		secret, "alice", "", shared.RelSigningKey{}, shared.RelPeerKey{},
	)
	if cliErr == nil {
		t.Fatal("the client should have failed: the server always refuses a connection without a known IdentityKey-per-relationship")
	}

	srvRes := <-srvCh
	if srvRes.err == nil {
		t.Fatal("the server should have explicitly refused a client without a known IdentityKey-per-relationship")
	}
}

// TestHandshakeE2EWithRelKeys covers the normal case of two parties who
// have already exchanged their IdentityKey-per-relationship at the invite
// bootstrap (RoomRegistry.AddSecret), no fingerprint to resolve, no cache,
// no network fetch: both sides verify Sig against a key already known by
// construction.
func TestHandshakeE2EWithRelKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	secret := []byte("shared-secret-handshake-rel-keys-test")

	clientRelKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatalf("GenerateRelSigningKey (client): %v", err)
	}
	clientEdPub, _, clientMLDSAPub, err := shared.RelSigningKeyPublicParts(clientRelKey)
	if err != nil {
		t.Fatalf("RelSigningKeyPublicParts (client): %v", err)
	}
	serverRelKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatalf("GenerateRelSigningKey (server): %v", err)
	}
	serverEdPub, _, serverMLDSAPub, err := shared.RelSigningKeyPublicParts(serverRelKey)
	if err != nil {
		t.Fatalf("RelSigningKeyPublicParts (server): %v", err)
	}

	type result struct {
		res shared.HandshakeResult
		err error
	}
	srvCh := make(chan result, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		defer conn.CloseNow()
		lookup := func(nonceClient, proof []byte) ([]byte, string, string, []byte, []byte, shared.RelPeerKey, shared.RelSigningKey, bool) {
			if _, ok := shared.VerifyRoomProof(secret, nonceClient, proof); ok {
				return secret, "test-room", "", nil, nil, shared.RelPeerKey{Pub: clientEdPub, MLDSAPub: clientMLDSAPub}, serverRelKey, true
			}
			return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		res, err := serverhs.DoServerHandshake(r.Context(), conn, lookup, nil)
		srvCh <- result{res, err}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	cliRes, err := clienths.DoClientHandshake(
		ctx, conn,
		secret, "alice", "", clientRelKey, shared.RelPeerKey{Pub: serverEdPub, MLDSAPub: serverMLDSAPub},
	)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	srvRes := <-srvCh
	if srvRes.err != nil {
		t.Fatalf("server handshake: %v", srvRes.err)
	}

	if !bytes.Equal(cliRes.SessionKey, srvRes.res.SessionKey) {
		t.Fatalf("session key diverge:\n  client: %x\n  server: %x",
			cliRes.SessionKey, srvRes.res.SessionKey)
	}
	if !bytes.Equal(srvRes.res.MatchedIdentityPub, []byte(clientEdPub)) {
		t.Errorf("MatchedIdentityPub = %x, want %x", srvRes.res.MatchedIdentityPub, clientEdPub)
	}
	if len(srvRes.res.PeerMLKEMPub) != mlkem.EncapsulationKeySize768 {
		t.Errorf("PeerMLKEMPub: want length %d, got %d", mlkem.EncapsulationKeySize768, len(srvRes.res.PeerMLKEMPub))
	}
}

// TestHandshakeE2EMissingSigningKeyRejected verifies that if secretLookup
// returns a valid peerKey (ClientHello.Sig verifies) but an empty
// mySigningKey, the server must explicitly reject
// (shared.ErrMissingSigningKey) BEFORE generating and sending ServerHello,
// never silently tolerate it and let the failure surface only later
// client-side as an unverifiable empty signature. Not a case reachable by
// any real caller (AddSecret/ReplaceSecret always require
// peerKey+mySigningKey together), but the gate must still hold for a future
// incorrect call site.
func TestHandshakeE2EMissingSigningKeyRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	secret := []byte("shared-secret-handshake-missing-signing-key-test")

	clientRelKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		t.Fatalf("GenerateRelSigningKey (client): %v", err)
	}
	clientEdPub, _, clientMLDSAPub, err := shared.RelSigningKeyPublicParts(clientRelKey)
	if err != nil {
		t.Fatalf("RelSigningKeyPublicParts (client): %v", err)
	}

	type result struct {
		res shared.HandshakeResult
		err error
	}
	srvCh := make(chan result, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		defer conn.CloseNow()
		// peerKey known and valid (the client verifies correctly), but
		// mySigningKey empty, exactly the scenario under test.
		lookup := func(nonceClient, proof []byte) ([]byte, string, string, []byte, []byte, shared.RelPeerKey, shared.RelSigningKey, bool) {
			if _, ok := shared.VerifyRoomProof(secret, nonceClient, proof); ok {
				return secret, "test-room", "", nil, nil, shared.RelPeerKey{Pub: clientEdPub, MLDSAPub: clientMLDSAPub}, shared.RelSigningKey{}, true
			}
			return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		res, err := serverhs.DoServerHandshake(r.Context(), conn, lookup, nil)
		srvCh <- result{res, err}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	_, cliErr := clienths.DoClientHandshake(
		ctx, conn,
		secret, "alice", "", clientRelKey, shared.RelPeerKey{},
	)
	if cliErr == nil {
		t.Fatal("the client should have failed: the server has no key to sign ServerHello toward it")
	}

	srvRes := <-srvCh
	if srvRes.err == nil {
		t.Fatal("the server should have explicitly refused a missing mySigningKey, not silently tolerated it")
	}
}

// TestHandshakeE2ERejectsMissingMLKEM verifies that the server explicitly
// rejects a ClientHello with an absent or wrong-length MLKEMPub,
// mandatory, same rigor already verified for a
// missing IdentityKey-per-relationship in TestHandshakeE2ENoRelKeyRejected.
// Builds the ClientHello by hand (bypassing DoClientHandshake, which always
// generates a valid ML-KEM key) to simulate a malformed payload/outdated
// peer.
func TestHandshakeE2ERejectsMissingMLKEM(t *testing.T) {
	secret := []byte("shared-secret-handshake-mlkem-reject-test-256bit")

	type result struct {
		res shared.HandshakeResult
		err error
	}
	srvCh := make(chan result, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		defer conn.CloseNow()
		lookup := func(nonceClient, proof []byte) ([]byte, string, string, []byte, []byte, shared.RelPeerKey, shared.RelSigningKey, bool) {
			if _, ok := shared.VerifyRoomProof(secret, nonceClient, proof); ok {
				return secret, "test-room", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, true
			}
			return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		res, err := serverhs.DoServerHandshake(r.Context(), conn, lookup, nil)
		srvCh <- result{res, err}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	nonceClient, err := shared.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	roomKey, err := shared.DeriveContactRoomKey(secret, shared.CurrentPeriod())
	if err != nil {
		t.Fatalf("DeriveContactRoomKey: %v", err)
	}
	sessionPub, err := shared.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	hello := shared.ClientHello{
		Version:     shared.HandshakeVersion,
		NonceClient: nonceClient,
		SessionPub:  sessionPub,
		// MLKEMPub deliberately absent, malformed payload to be rejected.
		RoomProof: shared.ComputeRoomProof(roomKey, nonceClient),
		Username:  "eve",
	}
	if err := wsjson.Write(context.Background(), conn, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	var srvHello shared.ServerHello
	if err := wsjson.Read(context.Background(), conn, &srvHello); err == nil {
		t.Fatal("the client should have received a close, not a ServerHello")
	}

	srvRes := <-srvCh
	if srvRes.err == nil {
		t.Fatal("the server should have explicitly refused a ClientHello without a valid MLKEMPub")
	}
	if !strings.Contains(srvRes.err.Error(), string(shared.ErrMissingHybridKEM)) {
		t.Errorf("server error = %q, want it to contain %q", srvRes.err.Error(), shared.ErrMissingHybridKEM)
	}
}
