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
	"sync"
	"time"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*UserSession
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*UserSession)}
}

func (s *SessionStore) Add(sess *UserSession) {
	s.mu.Lock()
	s.sessions[sess.UserID] = sess
	s.mu.Unlock()
}

// Get is not called from production code (server.go/handlers.go use
// RoomRegistry/Hub for routing), it is an inspection accessor used by
// the test suite (store_test.go, rooms_internal_test.go)
// to verify internal state after Add/Remove/CleanupStale, same role as
// EncryptTestSealedFrame in internal/client.
func (s *SessionStore) Get(userID string) (*UserSession, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[userID]
	s.mu.RUnlock()
	return sess, ok
}

func (s *SessionStore) Touch(userID string) {
	s.mu.Lock()
	if sess, ok := s.sessions[userID]; ok {
		sess.Touch()
	}
	s.mu.Unlock()
}

func (s *SessionStore) Remove(userID string) {
	s.mu.Lock()
	delete(s.sessions, userID)
	s.mu.Unlock()
}

func (s *SessionStore) GetAll() []*UserSession {
	s.mu.RLock()
	out := make([]*UserSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	s.mu.RUnlock()
	return out
}

func (s *SessionStore) Count() int {
	s.mu.RLock()
	n := len(s.sessions)
	s.mu.RUnlock()
	return n
}

func (s *SessionStore) CleanupStale(timeout time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int
	for id, sess := range s.sessions {
		if sess.IsStale(timeout) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}
