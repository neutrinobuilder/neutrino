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

package indoor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"neutrino/internal/keystore"
	"neutrino/internal/shared"
)

// maxFrameLen is the safety cap for a single length-prefixed frame on the
// TCP session, ample for a realistic contact-list/DeviceRecord payload,
// while still protecting against a peer declaring an absurd length.
const maxFrameLen = 4 << 20 // 4 MiB

// sessionAAD/tombstoneReplyAAD/tombstoneAckAAD bind each round's
// encryption to its own distinct protocol step, domain separation
// between the three rounds exchanged over the same session key.
const (
	sessionAAD        = "neutrino-indoor-payload-v1"
	tombstoneReplyAAD = "neutrino-indoor-tombstone-reply-v1"
	tombstoneAckAAD   = "neutrino-indoor-tombstone-ack-v1"
)

// writeFrame writes raw preceded by a 4-byte big-endian length.
func writeFrame(conn net.Conn, raw []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(raw)
	return err
}

// readFrame reads a length-prefixed frame written by writeFrame.
func readFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameLen {
		return nil, errors.New("indoor: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// randomNonce generates a challenge/response nonce.
func randomNonce() ([]byte, error) {
	n := make([]byte, nonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// runChallengeResponse runs the three-step challenge/response (see the
// package comment) and returns the derived session key, identical on
// both sides by construction, no exchange of different public keys
// needed: the SAME identity pub/priv is already known to both. initiator
// only distinguishes the order of messages on the wire (who sends the
// first nonce), no other role asymmetry.
func runChallengeResponse(conn net.Conn, identityPriv ed25519.PrivateKey, identityPub ed25519.PublicKey, initiator bool) ([]byte, error) {
	var nonceA, nonceB []byte
	var err error

	if initiator {
		if nonceA, err = randomNonce(); err != nil {
			return nil, err
		}
		if err = writeFrame(conn, nonceA); err != nil {
			return nil, err
		}

		respFrame, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		if len(respFrame) != nonceLen+ed25519.SignatureSize {
			return nil, errors.New("indoor: malformed challenge response")
		}
		nonceB = respFrame[:nonceLen]
		sigB := respFrame[nonceLen:]
		if !VerifyChallenge(identityPub, nonceA, nonceB, sigB) {
			return nil, errors.New("indoor: invalid peer signature, not the same identity")
		}

		sigA := SignChallenge(identityPriv, nonceB, nonceA)
		if err = writeFrame(conn, sigA); err != nil {
			return nil, err
		}
	} else {
		aFrame, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		if len(aFrame) != nonceLen {
			return nil, errors.New("indoor: malformed first nonce")
		}
		nonceA = aFrame

		if nonceB, err = randomNonce(); err != nil {
			return nil, err
		}
		sigB := SignChallenge(identityPriv, nonceA, nonceB)
		resp := append(append([]byte(nil), nonceB...), sigB...)
		if err = writeFrame(conn, resp); err != nil {
			return nil, err
		}

		sigAFrame, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		if !VerifyChallenge(identityPub, nonceB, nonceA, sigAFrame) {
			return nil, errors.New("indoor: invalid peer signature, not the same identity")
		}
	}

	return DeriveSessionKey(identityPriv, nonceA, nonceB)
}

// exchangeBytes sends myData (encrypted under sessionKey, bound to aad)
// and returns the peer's own, fixed order (initiator writes then
// reads, responder reads then writes) to avoid a deadlock on a single
// TCP connection that is full-duplex but without dedicated
// application-level buffering. The one primitive every round of the
// session (payload, tombstone replies, tombstone acks) is built on.
func exchangeBytes(conn net.Conn, sessionKey []byte, aad string, myData []byte, initiator bool) ([]byte, error) {
	enc, err := shared.Encrypt(sessionKey, myData, []byte(aad))
	if err != nil {
		return nil, err
	}

	send := func() error { return writeFrame(conn, []byte(enc)) }
	recv := func() ([]byte, error) {
		frame, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		return shared.Decrypt(sessionKey, string(frame), []byte(aad))
	}

	if initiator {
		if err := send(); err != nil {
			return nil, err
		}
		return recv()
	}
	peer, err := recv()
	if err != nil {
		return nil, err
	}
	if err := send(); err != nil {
		return nil, err
	}
	return peer, nil
}

// TombstoneRound bundles the three steps a session runs, after the base
// SyncPayload exchange, to reconcile contact deletions with the peer,
// same explicit reply/ack protocol as the knock channel (device_sync),
// run here over the already-open TCP connection instead of separate
// knocks:
//   - ComputeReplies: given the peer's Contacts just received, returns
//     this side's DeletedContacts rows for any already known deleted
//     locally, sent back to the peer as the tombstone reply.
//   - ApplyAndAck: adopts the peer's own reply rows (deleting any
//     matching live contact, merging ConfirmedSiblings) and returns the
//     IdentityPubs to ack as adopted.
//   - ConfirmAcked: marks peerDeviceID confirmed, on this side's own
//     rows, for every IdentityPub the peer just acked.
type TombstoneRound struct {
	ComputeReplies func(peerContacts []keystore.Contact) []keystore.DeletedContact
	ApplyAndAck    func(replies []keystore.DeletedContact) [][]byte
	ConfirmAcked   func(acked [][]byte, peerDeviceID []byte)
}

// runTombstoneRounds runs TombstoneRound's reply and ack exchanges over
// the same connection/session key as the base payload exchange, using
// peer (just received from exchangePayload) as input.
func runTombstoneRounds(conn net.Conn, sessionKey []byte, peer SyncPayload, initiator bool, round TombstoneRound) error {
	myReplies := round.ComputeReplies(peer.Contacts)
	repliesJSON, err := json.Marshal(myReplies)
	if err != nil {
		return err
	}
	peerRepliesJSON, err := exchangeBytes(conn, sessionKey, tombstoneReplyAAD, repliesJSON, initiator)
	if err != nil {
		return err
	}
	var peerReplies []keystore.DeletedContact
	if err := json.Unmarshal(peerRepliesJSON, &peerReplies); err != nil {
		return err
	}

	myAcks := round.ApplyAndAck(peerReplies)
	acksJSON, err := json.Marshal(myAcks)
	if err != nil {
		return err
	}
	peerAcksJSON, err := exchangeBytes(conn, sessionKey, tombstoneAckAAD, acksJSON, initiator)
	if err != nil {
		return err
	}
	var peerAcks [][]byte
	if err := json.Unmarshal(peerAcksJSON, &peerAcks); err != nil {
		return err
	}
	round.ConfirmAcked(peerAcks, peer.Device.DeviceID)
	return nil
}

// RunSession runs the entire indoor session over an already-established
// TCP connection (dial or accept, see discovery.go): mutual
// challenge/response with the SAME identity key known to both sides,
// exchange of the encrypted SyncPayload, then the tombstone
// reply/ack rounds (round), returns the SyncPayload received from the
// peer (the caller does MergeContacts/AppendKnownDevice). initiator =
// true for whoever opened the connection (whoever received the
// multicast announcement and connected to the announcer).
func RunSession(conn net.Conn, deadline time.Duration, identityPriv ed25519.PrivateKey, myPayload SyncPayload, initiator bool, round TombstoneRound) (SyncPayload, error) {
	if len(identityPriv) != ed25519.PrivateKeySize {
		return SyncPayload{}, errors.New("indoor: missing or invalid identity key")
	}
	identityPub := identityPriv.Public().(ed25519.PublicKey)

	_ = conn.SetDeadline(time.Now().Add(deadline))

	sessionKey, err := runChallengeResponse(conn, identityPriv, identityPub, initiator)
	if err != nil {
		return SyncPayload{}, err
	}
	defer func() {
		for i := range sessionKey {
			sessionKey[i] = 0
		}
	}()

	plain, err := MarshalSyncPayload(myPayload)
	if err != nil {
		return SyncPayload{}, err
	}
	peerRaw, err := exchangeBytes(conn, sessionKey, sessionAAD, plain, initiator)
	if err != nil {
		return SyncPayload{}, err
	}
	peer, err := UnmarshalSyncPayload(peerRaw)
	if err != nil {
		return SyncPayload{}, err
	}

	if err := runTombstoneRounds(conn, sessionKey, peer, initiator, round); err != nil {
		return SyncPayload{}, err
	}
	return peer, nil
}
