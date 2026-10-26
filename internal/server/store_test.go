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
	"testing"
	"time"

	serverhs "neutrino/internal/server"
)

func TestSessionStoreAddGetRemove(t *testing.T) {
	s := serverhs.NewSessionStore()
	s.Add(&serverhs.UserSession{UserID: "u1", Username: "alice"})

	got, ok := s.Get("u1")
	if !ok {
		t.Fatal("Get: want found")
	}
	if got.Username != "alice" {
		t.Fatalf("Username: want 'alice', got %q", got.Username)
	}

	s.Remove("u1")
	if _, ok := s.Get("u1"); ok {
		t.Fatal("Get after Remove: want not found")
	}
}

func TestSessionStoreGetMissing(t *testing.T) {
	s := serverhs.NewSessionStore()
	if _, ok := s.Get("missing"); ok {
		t.Fatal("Get on an empty store: want not found")
	}
}

func TestSessionStoreGetAllAndCount(t *testing.T) {
	s := serverhs.NewSessionStore()
	if s.Count() != 0 {
		t.Fatal("Count on an empty store: want 0")
	}
	s.Add(&serverhs.UserSession{UserID: "u1", Username: "alice"})
	s.Add(&serverhs.UserSession{UserID: "u2", Username: "bob"})

	if s.Count() != 2 {
		t.Fatalf("Count: want 2, got %d", s.Count())
	}
	all := s.GetAll()
	if len(all) != 2 {
		t.Fatalf("GetAll: want 2 sessions, got %d", len(all))
	}
}

func TestSessionStoreTouchUpdatesLastSeen(t *testing.T) {
	s := serverhs.NewSessionStore()
	old := time.Now().UTC().Add(-time.Hour)
	s.Add(&serverhs.UserSession{UserID: "u1", LastSeen: old})

	s.Touch("u1")

	got, _ := s.Get("u1")
	if !got.LastSeen.After(old) {
		t.Fatal("Touch: LastSeen not updated")
	}
}

func TestSessionStoreTouchUnknownIsNoop(t *testing.T) {
	s := serverhs.NewSessionStore()
	s.Touch("missing") // must not panic
}

func TestSessionStoreCleanupStale(t *testing.T) {
	s := serverhs.NewSessionStore()
	s.Add(&serverhs.UserSession{UserID: "fresh", LastSeen: time.Now().UTC()})
	s.Add(&serverhs.UserSession{UserID: "stale", LastSeen: time.Now().UTC().Add(-time.Hour)})

	removed := s.CleanupStale(10 * time.Minute)
	if removed != 1 {
		t.Fatalf("CleanupStale: want 1 removed, got %d", removed)
	}
	if _, ok := s.Get("stale"); ok {
		t.Fatal("CleanupStale: the stale session is still present")
	}
	if _, ok := s.Get("fresh"); !ok {
		t.Fatal("CleanupStale: the fresh session was wrongly removed")
	}
}

func TestUserSessionIsStale(t *testing.T) {
	sess := &serverhs.UserSession{LastSeen: time.Now().UTC().Add(-time.Hour)}
	if !sess.IsStale(time.Minute) {
		t.Fatal("IsStale: want true for an hour-old session with a one-minute timeout")
	}
	fresh := &serverhs.UserSession{LastSeen: time.Now().UTC()}
	if fresh.IsStale(time.Minute) {
		t.Fatal("IsStale: want false for a session just touched")
	}
}
