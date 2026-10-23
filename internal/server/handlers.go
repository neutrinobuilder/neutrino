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

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"neutrino/internal/shared"
)

type appCtx struct {
	registry     *RoomRegistry
	limiter      *RateLimiter
	identityPriv ed25519.PrivateKey         // to decrypt incoming knocks
	mlkemDecap   *mlkem.DecapsulationKey768 // durable twin of identityPriv — nil = hybrid knocks can't be decrypted, falls back to classic knocks only
	knockCh      chan<- shared.KnockPayload // nil if the server doesn't support knocks
	// knownContactPubs returns the Ed25519 pubkeys of all known contacts —
	// read on every knock, never nil itself (see RunOnListener), reflects
	// the current address book even if it changes during the process's
	// life. Mandatory mutuality (Briar-style model): a knock from someone
	// who isn't already a contact is discarded BEFORE ECIES decryption —
	// see handleKnock, filter via KnockDHTag.
	knownContactPubs    func() [][]byte
	pingInterval        time.Duration // WS keepalive interval
	cleanupInterval     time.Duration // rate limiter + stale session cleanup interval
	sessionStaleTimeout time.Duration // threshold for RoomRegistry.CleanupStaleSessions — see ServerConfig.SessionStaleTimeout
	// silenced (nil = never silenced): see ServerConfig.Silenced — if
	// isSilenced() is true, every entry point closes immediately with no
	// protocol response, before touching identityPriv/mlkemDecap.
	silenced func() bool
}

func (a *appCtx) isSilenced() bool {
	return a.silenced != nil && a.silenced()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// GET /health
func (a *appCtx) handleHealth(w http.ResponseWriter, r *http.Request) {
	if a.isSilenced() {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"users":  a.registry.TotalSessions(),
	})
}

// maxKnockBodyBytes limits POST /knock's HTTP body. Sized to fit
// KnockPayload.RelBootstrap — two complete relationship key pairs
// (Ed25519+ML-KEM-768+ML-DSA-65 each, ~6.3KB raw) plus
// RelBootstrapPayload.Sig/SigMLDSA (root IdentityKey signature on the
// bootstrap), which push the encrypted knock to ~21.6KB on its own
// after hybrid ECIES encryption and base64 encoding. Without enough
// headroom here, the body
// gets truncated by io.LimitReader, the truncated JSON fails to unmarshal,
// and every rel_init fails with HTTP 400. The rate limiter (10
// requests/minute per IP, see a.limiter below) remains the primary
// anti-flood defense on this pre-authentication endpoint, not the size of
// a single body.
const maxKnockBodyBytes = 26000

// maxDeviceSyncBodyBytes limits POST /device-sync's body: a whole address
// book with every relationship key. Applied only after the header tag
// has proven the sender holds this identity's key.
const maxDeviceSyncBodyBytes = 8 << 20

// POST /knock — receives a JSON envelope (shared.KnockEnvelope): a
// plaintext static-static DH tag (shared.KnockDHTag) plus an ECIES-encrypted
// payload toward our identity key (shared.EncryptKnock).
func (a *appCtx) handleKnock(w http.ResponseWriter, r *http.Request) {
	if a.isSilenced() {
		http.NotFound(w, r)
		return
	}
	if !a.limiter.AllowRequest(r.RemoteAddr) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if a.knockCh == nil || a.identityPriv == nil {
		http.Error(w, "not supported", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxKnockBodyBytes))
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var env shared.KnockEnvelope
	if err := json.Unmarshal(body, &env); err != nil || len(env.Tag) == 0 || env.Payload == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Pre-decryption filter via KnockDHTag: a tag that matches neither the
	// self-probe nor any known contact is discarded WITHOUT EVER running
	// DecryptKnock (no ECDH X25519+AES-GCM on a non-mutual knock). Identical
	// response (202) whether the knock gets processed or discarded for
	// non-mutuality — there must be no way to distinguish from the outside
	// "this isn't my contact" from "I processed it", otherwise mutuality
	// itself would become a channel to enumerate the recipient's address
	// book.
	myPub, _ := a.identityPriv.Public().(ed25519.PublicKey)
	var matchedPub ed25519.PublicKey
	if selfTag, terr := shared.KnockDHTag(a.identityPriv, myPub); terr == nil && hmac.Equal(env.Tag, selfTag) {
		matchedPub = myPub
	}
	if matchedPub == nil && a.knownContactPubs != nil {
		for _, pub := range a.knownContactPubs() {
			if tag, terr := shared.KnockDHTag(a.identityPriv, pub); terr == nil && hmac.Equal(env.Tag, tag) {
				matchedPub = pub
				break
			}
		}
	}
	if matchedPub == nil {
		// Diagnostics: without this, a mutuality-filter failure is
		// invisible even with `neutrino debug`/Debug active — that
		// mechanism (internal/client.Dbg, see dbg() in this package)
		// receives a knock only AFTER it has passed this filter and
		// decryption. Only a prefix of the tag is logged (8 of 32 bytes),
		// never the whole tag or the encrypted payload.
		dbg("knock: non-mutual tag, discarded (tag=%s…)", base64.RawStdEncoding.EncodeToString(env.Tag[:min(8, len(env.Tag))]))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	a.deliverKnock(w, env, matchedPub)
}

// POST /device-sync — a knock from another device of this same identity
// (see shared.DeviceSyncPath). The tag in the header must be this
// identity's own, checked before reading anything else: a mismatch gets
// the same 202 as a non-mutual knock, so the endpoint reveals nothing.
// Only then the body may be as large as an address book.
func (a *appCtx) handleDeviceSync(w http.ResponseWriter, r *http.Request) {
	if a.isSilenced() {
		http.NotFound(w, r)
		return
	}
	if !a.limiter.AllowRequest(r.RemoteAddr) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if a.knockCh == nil || a.identityPriv == nil {
		http.Error(w, "not supported", http.StatusNotImplemented)
		return
	}
	tag, err := base64.StdEncoding.DecodeString(r.Header.Get(shared.DeviceSyncTagHeader))
	if err != nil || len(tag) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	myPub, _ := a.identityPriv.Public().(ed25519.PublicKey)
	if selfTag, terr := shared.KnockDHTag(a.identityPriv, myPub); terr != nil || !hmac.Equal(tag, selfTag) {
		dbg("device-sync: tag not from our own identity, discarded")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceSyncBodyBytes+1))
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxDeviceSyncBodyBytes {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	var env shared.KnockEnvelope
	if err := json.Unmarshal(body, &env); err != nil || !hmac.Equal(env.Tag, tag) || env.Payload == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a.deliverKnock(w, env, myPub)
}

// deliverKnock decrypts an envelope whose tag already matched matchedPub
// and hands the payload to the knock channel — the part shared by POST
// /knock and POST /device-sync.
func (a *appCtx) deliverKnock(w http.ResponseWriter, env shared.KnockEnvelope, matchedPub ed25519.PublicKey) {
	payload, err := shared.DecryptKnock(a.identityPriv, a.mlkemDecap, env.Payload)
	if err != nil {
		dbg("knock: decryption failed despite a mutual tag: %v", err)
		http.Error(w, "invalid knock", http.StatusBadRequest)
		return
	}
	// Defense in depth: the decrypted sender must be exactly the contact
	// (or ourselves) whose tag passed the filter above — the tag alone
	// already guarantees possession of a known private key, this verifies
	// it wasn't used to declare a different identity inside the encrypted
	// payload. Same 202 response, same reason as above.
	if !bytes.Equal(payload.FromIdentityPub, matchedPub) {
		dbg("knock: FromIdentityPub in the payload doesn't match the mutual tag's pubkey (type=%q from=%s)", payload.Type, payload.FromUsername)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	dbg("knock: decrypted successfully type=%q from=%s", payload.Type, payload.FromUsername)
	select {
	case a.knockCh <- payload:
		// No RoomRegistry self-registration here: whoever receives an
		// invite (this knock) always connects ONLY AS A CLIENT toward the
		// host who invited them (knock.FromAddr) — never runs their own
		// server for that room, so a secret registered here, on THIS OWN
		// registry, would never be consulted by anyone (RoomRegistry.
		// LookupSecret only runs host-side, for INCOMING connections on
		// its own server). The registration that actually matters — with
		// the real relationship keys — remains the one the HOST performs
		// on ITS OWN registry when generating the invite (cmdInvite,
		// internal/client/tui).
		w.WriteHeader(http.StatusAccepted)
	default:
		dbg("knock: knockCh full, discarded type=%q from=%s", payload.Type, payload.FromUsername)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}
}
