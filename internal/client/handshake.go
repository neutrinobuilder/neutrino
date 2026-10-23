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
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"neutrino/internal/i18n"
	"neutrino/internal/shared"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// ErrInvalidServerSig signals that ServerHello.Sig (or SigMLDSA) failed
// verification against the host's locally known
// IdentityKey-per-relationship — distinct from a network/transport
// error, checkable by the caller with errors.Is even after
// Connect/ConnectWithRetry have wrapped the error in a localized message
// (see client.go:Connect). One real cause: the local copy of the host's
// key falling out of sync with a regeneration of its
// identity-key-per-relationship that never propagated (see
// cmdJoin/case roomErrMsg in tui.go, which uses this sentinel to force
// a new rel_init exchange instead of failing forever with the same
// stale key).
var ErrInvalidServerSig = errors.New("invalid server signature")

// ErrAlreadyConnectedElsewhere signals that the server rejected this
// connection because a DIFFERENT device of OUR OWN identity is already
// connected to this room — "one device per identity per room"
// (shared.ErrAlreadyConnected). Checkable with errors.Is even after the
// localized wrapping by Connect/ConnectWithRetry, the same principle as
// ErrInvalidServerSig above — distinguishes this case (which resolves
// ONLY when the other device disconnects, never a network issue) from a
// generic failure, for which the caller (tui.go) uses a
// dedicated retry loop instead of the ordinary exponential backoff.
var ErrAlreadyConnectedElsewhere = errors.New("already connected from another device")

// DoClientHandshake performs the client-side handshake on an already
// open WebSocket connection to the contact's node.
//
// Sequence:
//  1. Generate nonce_client and an ephemeral X25519 pair + an ephemeral ML-KEM-768 pair
//  2. Compute room_proof = HMAC-SHA256(room_key, nonce_client)
//  3. Sign (nonce_client || session_pub) with OUR OWN IdentityKey-per-relationship toward this host
//  4. Send ClientHello
//  5. Receive ServerHello
//  6. Verify Sig with the host's IdentityKey-per-relationship (known from the invite bootstrap)
//  7. Compute session_key via hybrid X25519+ML-KEM-768 + HKDF (the transcript includes both session pubs)
func DoClientHandshake(
	ctx context.Context,
	conn *websocket.Conn,
	contactSecret []byte,
	username string,
	eciesPubB64 string, // base64 of our X25519 pubkey for peer-to-peer ECIES
	mySigningKey shared.RelSigningKey, // our own IdentityKey-per-relationship toward this host
	hostKey shared.RelPeerKey, // the host's IdentityKey-per-relationship, known from the invite bootstrap
) (shared.HandshakeResult, error) {
	// 1. nonce_client
	nonceClient, err := shared.RandomBytes(32)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_nonce", err))
	}
	Dbg("hs[%s]: nonce_client=%x…", username, nonceClient[:4])

	// 2. ephemeral X25519 pair
	sessionPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_keygen", err))
	}
	sessionPubBytes := sessionPriv.PublicKey().Bytes()
	Dbg("hs[%s]: ephemeral X25519 generated", username)

	// 2b. ephemeral ML-KEM-768 pair (PQC, mandatory)
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_keygen", err))
	}
	mlkemPubBytes := mlkemDK.EncapsulationKey().Bytes()
	Dbg("hs[%s]: ephemeral ML-KEM-768 generated", username)

	// 3. room_proof
	roomKey, err := shared.DeriveContactRoomKey(contactSecret, shared.CurrentPeriod())
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_room_key", err))
	}
	roomProof := shared.ComputeRoomProof(roomKey, nonceClient)
	Dbg("hs[%s]: room_proof HMAC computed", username)

	// 4. build ClientHello
	hello := shared.ClientHello{
		Version:     shared.HandshakeVersion,
		NonceClient: nonceClient,
		SessionPub:  sessionPubBytes,
		MLKEMPub:    mlkemPubBytes,
		RoomProof:   roomProof,
		Username:    username,
		ECIESPub:    eciesPubB64,
	}
	if len(mySigningKey.Priv) == ed25519.PrivateKeySize {
		payload := shared.ClientSigPayload(nonceClient, sessionPubBytes)
		hello.Sig = ed25519.Sign(mySigningKey.Priv, payload)
		if len(mySigningKey.MLDSASeed) == mldsa65.SeedSize {
			var seed [mldsa65.SeedSize]byte
			copy(seed[:], mySigningKey.MLDSASeed)
			_, mldsaPriv := mldsa65.NewKeyFromSeed(&seed)
			sig := make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(mldsaPriv, payload, nil, true, sig); err == nil {
				hello.SigMLDSA = sig
			}
		}
		Dbg("hs[%s]: signing with the per-relationship IdentityKey", username)
	}

	// 5. send ClientHello
	if err := wsjson.Write(ctx, conn, hello); err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_send_hello", err))
	}
	Dbg("hs[%s]: ClientHello sent", username)

	// 6. receive ServerHello
	var srvHello shared.ServerHello
	if err := wsjson.Read(ctx, conn, &srvHello); err != nil {
		// The server closes BEFORE sending ServerHello for
		// shared.ErrAlreadyConnected (post-handshake rejection) —
		// distinguished here from a generic network/read failure,
		// because the caller must be able to choose a dedicated retry
		// loop instead of the ordinary backoff.
		var ce websocket.CloseError
		if errors.As(err, &ce) && ce.Code == websocket.StatusPolicyViolation && ce.Reason == string(shared.ErrAlreadyConnected) {
			return shared.HandshakeResult{}, ErrAlreadyConnectedElsewhere
		}
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_recv_hello", err))
	}
	Dbg("hs[%s]: ServerHello received", username)

	// 7. verify Sig with the host's IdentityKey-per-relationship — known
	// from the invite bootstrap, never a global key nor a fingerprint to
	// resolve (the same principle already applied server-side for
	// ClientHello.Sig, see server/handshake.go). SigMLDSA (if the host
	// sends it) is verified in addition, never blocking if absent.
	if len(hostKey.Pub) != ed25519.PublicKeySize {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_server_unknown_identity"))
	}
	// Diagnostics: compare with the twin line server-side
	// ("handshake: label=... mySigningKey.Pub=...",
	// internal/server/handshake.go) to establish whether this is a real
	// key mismatch or an issue elsewhere (payload, transcript, MLDSA key).
	Dbg("hs[%s]: verifying ServerHello with hostKey.Pub=%s", username, base64.RawStdEncoding.EncodeToString(hostKey.Pub))
	srvPayload := shared.ServerSigPayload(nonceClient, srvHello.NonceServer, srvHello.SessionPub)
	if !ed25519.Verify(hostKey.Pub, srvPayload, srvHello.Sig) {
		return shared.HandshakeResult{}, fmt.Errorf("%s: %w", i18n.T("handshake.err_invalid_sig", errors.New("ed25519 verify failed")), ErrInvalidServerSig)
	}
	if len(hostKey.MLDSAPub) > 0 && len(srvHello.SigMLDSA) > 0 {
		mldsaPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(hostKey.MLDSAPub)
		if err == nil {
			if !mldsa65.Verify(mldsaPub.(*mldsa65.PublicKey), srvPayload, nil, srvHello.SigMLDSA) {
				return shared.HandshakeResult{}, fmt.Errorf("%s: %w", i18n.T("handshake.err_invalid_sig", errors.New("ml-dsa verify failed")), ErrInvalidServerSig)
			}
		}
	}
	Dbg("hs[%s]: server signature verified ✓", username)

	// 8. X25519 DH + ML-KEM decapsulate + session key
	srvPub, err := ecdh.X25519().NewPublicKey(srvHello.SessionPub)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_server_session", err))
	}
	dhSecret, err := sessionPriv.ECDH(srvPub)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_ecdh", err))
	}
	if len(srvHello.MLKEMCiphertext) != mlkem.CiphertextSize768 {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_server_mlkem_required"))
	}
	mlkemSS, err := mlkemDK.Decapsulate(srvHello.MLKEMCiphertext)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_mlkem_decap", err))
	}
	sessionKey, err := shared.DeriveSessionKey(mlkemSS, dhSecret, nonceClient, srvHello.NonceServer, sessionPubBytes, srvHello.SessionPub)
	if err != nil {
		return shared.HandshakeResult{}, errors.New(i18n.T("handshake.err_session_key", err))
	}
	Dbg("hs[%s]: X25519 DH + ML-KEM-768 + HKDF → session_key ✓", username)

	return shared.HandshakeResult{
		SessionKey:       sessionKey,
		ClientMLKEMDecap: mlkemDK,
	}, nil
}
