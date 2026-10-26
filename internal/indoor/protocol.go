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

// Package indoor implements "indoor" (LAN) synchronization: two neutrino
// instances that ALREADY hold the same identity (duplicated via `neutrino
// restore`, an offline channel) discover each other on the local
// network, a proprietary UDP multicast, not mDNS, and exchange contact
// lists plus mutual registration as known devices
// (Keystore.KnownDevices) over an encrypted TCP connection.
//
// No ECDH is needed for the session key: both sides hold the
// same Ed25519 identity private key (it's the same duplicated identity,
// not two different identities talking to each other), the session is
// independently derivable on both sides with HKDF-SHA256 over the same
// secret material, after a challenge/response that proves mutual
// possession.
package indoor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"neutrino/internal/keystore"
)

// MulticastAddr is the UDP multicast group/port dedicated to discovery,
// local scope (239.255.0.0/16, IANA "organization-local"), never routed
// beyond the LAN.
const MulticastAddr = "239.255.42.99:42424"

// TCPPort is the port each instance listens on for the actual sync session
// (challenge-response + encrypted payload), after the multicast rendezvous.
const TCPPort = 42425

// ProtocolVersion identifies the packet format, a peer with a different
// version is silently ignored (never a noisy error for a simple build
// mismatch).
const ProtocolVersion = 1

// SessionHKDFInfo is the indoor session's HKDF label, the same role as
// "neutrino-session-v1" for the WebSocket handshake, a separate domain.
const SessionHKDFInfo = "neutrino-indoor-v1"

// SyncWindow is the duration of a /sec-indoor-sync session (announce +
// listen): enough to find a peer on the same LAN without staying open
// indefinitely.
const SyncWindow = 60 * time.Second

// AnnounceInterval is how often the multicast announcement repeats for the
// whole duration of SyncWindow.
const AnnounceInterval = 2 * time.Second

// nonceLen is the byte length of each challenge/response nonce.
const nonceLen = 32

// AnnouncePacket is the packet broadcast on the multicast group, ONLY the
// truncated identity pub hash, never the identity in the clear: even an
// "I'm here" announcement should be limited to those who already know that
// specific identity (anyone on the same network can see it). InstanceID (8
// random bytes, generated once per sync session) lets a process recognize
// and discard its own announcements, multicast loopback is often enabled
// by default on the local host, and two test processes on the same
// machine still share the same identity.
type AnnouncePacket struct {
	Version      int    `json:"v"`
	IdentityHash []byte `json:"h"`
	InstanceID   []byte `json:"i"`
}

// IdentityHash computes the truncated (16-byte) hash of an Ed25519
// identity pubkey, used ONLY for the multicast rendezvous (never to
// derive cryptographic material: that uses the full private key, see
// DeriveSessionKey).
func IdentityHash(identityPub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(identityPub)
	return append([]byte(nil), sum[:16]...)
}

// EncodeAnnounce/DecodeAnnounce serialize AnnouncePacket for the UDP wire.
func EncodeAnnounce(pkt AnnouncePacket) ([]byte, error) {
	return json.Marshal(pkt)
}

func DecodeAnnounce(raw []byte) (AnnouncePacket, error) {
	var pkt AnnouncePacket
	err := json.Unmarshal(raw, &pkt)
	return pkt, err
}

// challengeMsg is the message signed during the challenge/response, binds
// the two nonces in the given order, so A's signature (over
// nonceA‖nonceB) can never be reused as B's signature (over
// nonceB‖nonceA), even if the two nonces happened to coincide.
func challengeMsg(first, second []byte) []byte {
	msg := make([]byte, 0, len(first)+len(second))
	msg = append(msg, first...)
	msg = append(msg, second...)
	return msg
}

// SignChallenge signs challengeMsg(first, second) with the identity
// private key (the SAME on both sides, that's what proves possession).
func SignChallenge(identityPriv ed25519.PrivateKey, first, second []byte) []byte {
	return ed25519.Sign(identityPriv, challengeMsg(first, second))
}

// VerifyChallenge verifies a signature produced by SignChallenge.
func VerifyChallenge(identityPub ed25519.PublicKey, first, second, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	return ed25519.Verify(identityPub, challengeMsg(first, second), sig)
}

// DeriveSessionKey derives the AES-256-GCM session key from the identity
// private key (secret material already shared by both sides by
// construction, no ECDH) and the two challenge/response nonces as salt,
// so every session has a different key even if repeated several times with
// the same peer, despite starting from the same private key.
func DeriveSessionKey(identityPriv ed25519.PrivateKey, nonceA, nonceB []byte) ([]byte, error) {
	salt := challengeMsg(nonceA, nonceB)
	r := hkdf.New(sha256.New, identityPriv, salt, []byte(SessionHKDFInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// SyncPayload is the encrypted content exchanged over the TCP session, in
// both directions (same type, each side sends its OWN): the contact list
// to merge (Keystore.MergeContacts, the same function used by `sync
// import`), the sender's OWN DeviceRecord (registered on the other side
// via Keystore.AppendKnownDevice, not just the shared identity that led
// to the sync, but the FULL list of sibling identities present on the
// sending device at that moment, needed for remote_nuke's multi-identity
// fan-out), and KnownDevices, every OTHER sibling device the sender
// already knows about, registered via Keystore.MergeKnownDevices so that
// knowledge of a sibling spreads transitively between devices that have
// never synced with each other directly. NukedDevicePubs spreads the
// same way, gossip-style (Keystore.MergeNukedDevicePubs): every sibling
// device known to have been nuked, driving the retry queue for any
// not-yet-acked SiblingRevocations entry toward it.
type SyncPayload struct {
	Contacts        []keystore.Contact      `json:"contacts,omitempty"`
	Device          keystore.DeviceRecord   `json:"device"`
	KnownDevices    []keystore.DeviceRecord `json:"known_devices,omitempty"`
	NukedDevicePubs [][]byte                `json:"nuked_device_pubs,omitempty"`
}

// MarshalSyncPayload/UnmarshalSyncPayload serialize SyncPayload for
// encryption (shared.Encrypt/Decrypt, the same AES-256-GCM used throughout
// the project, see session.go).
func MarshalSyncPayload(p SyncPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalSyncPayload(raw []byte) (SyncPayload, error) {
	var p SyncPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return SyncPayload{}, err
	}
	if len(p.Device.DeviceID) == 0 {
		return SyncPayload{}, errors.New("indoor: payload without DeviceID")
	}
	return p, nil
}
