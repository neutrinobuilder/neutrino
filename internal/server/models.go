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
	"time"
)

// Message is the wire format for broadcast chat messages.
// The server never stores these; it only fans them out to connected clients.
type Message struct {
	FromUserID string    `json:"from_user_id"`
	Text       string    `json:"text"` // AES-256-GCM encrypted with sender's sender_key
	Username   string    `json:"username"`
	Timestamp  time.Time `json:"timestamp"`
	Sig        string    `json:"sig,omitempty"`
	SigTS      string    `json:"sig_ts,omitempty"`
}

type UserSession struct {
	UserID     string
	Username   string
	SessionKey []byte
	CreatedAt  time.Time
	LastSeen   time.Time
	SessionPub string // base64 X25519 public key for this session (for ECIES)
	// IdentityPub is the known IdentityKey-per-relationship for the secret
	// used, see HandshakeResult.MatchedIdentityPub. For the host's
	// exclusive use (never relayed to other members via
	// wsInitMsg/wsUserJoined).
	IdentityPub []byte
	// RootIdentityPub is this session's STABLE (root) identity, see
	// HandshakeResult.MatchedRootIdentityPub, the same one used by
	// ClaimIdentitySlot/roomDelivery (never the one that rotates, unlike
	// IdentityPub above). Used by RoomRegistry.KickMember to resolve which
	// delivery queue to forget starting from a session userID.
	RootIdentityPub []byte
	MLKEMPub        []byte // this connection's ML-KEM-768 encapsulation key, see HandshakeResult.PeerMLKEMPub
}

func (s *UserSession) Touch() {
	s.LastSeen = time.Now().UTC()
}

func (s *UserSession) IsStale(d time.Duration) bool {
	return time.Since(s.LastSeen) > d
}
