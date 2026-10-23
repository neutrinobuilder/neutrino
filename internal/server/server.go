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
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"net"
	"net/http"
	"time"

	"neutrino/internal/shared"
)

// ServerConfig holds the server's optional parameters. The zero value uses the defaults.
type ServerConfig struct {
	PingInterval    time.Duration // WS keepalive; default 1m — a single missed ping isn't enough to declare the connection dead, see the comment on the ping/pong goroutine in ws.go
	CleanupInterval time.Duration // rate limiter + stale session cleanup; default 5m
	// SessionStaleTimeout: UserSession.IsStale threshold for
	// RoomRegistry.CleanupStaleSessions, a backup safety net relative to
	// the ping/pong watchdog (see the comment on CleanupStaleSessions) —
	// default 24h, deliberately long: LastSeen only advances on actual chat
	// frames (room.sessions.Touch in ws.go, never on ping/pong), so a
	// connected but silent member for hours is "stale" by this metric
	// alone despite being perfectly online — a short timeout would wrongly
	// evict them. Only meant to eventually recover a session whose
	// deferred removal never fired for some unexpected reason.
	SessionStaleTimeout time.Duration

	// Silenced (nil = never silenced): APPLICATION-level silencing of this
	// listener — used for the previous hidden service after a rotation
	// has been confirmed by all contacts. Does
	// not close the onion service/listener itself (documented deadlock risk
	// in the bine library when closing a single *tor.OnionService without
	// stopping the whole Tor process) — when Silenced()
	// returns true, every entry point closes the connection immediately
	// BEFORE any handshake/decryption, without touching
	// identityPriv/mlkemDecap. The Tor descriptor stays published on HSDir,
	// but no meaningful protocol response reaches whoever contacts it
	// anymore.
	Silenced func() bool
}

func (c ServerConfig) ping() time.Duration {
	if c.PingInterval > 0 {
		return c.PingInterval
	}
	return time.Minute
}

func (c ServerConfig) cleanup() time.Duration {
	if c.CleanupInterval > 0 {
		return c.CleanupInterval
	}
	return 5 * time.Minute
}

func (c ServerConfig) sessionStale() time.Duration {
	if c.SessionStaleTimeout > 0 {
		return c.SessionStaleTimeout
	}
	return 24 * time.Hour
}

// RunOnListener starts the HTTP/WebSocket server on the given listener
// (typically a Tor hidden service). Doesn't use TLS: the transport is
// protected by Tor. identityPriv and knockCh enable the POST /knock
// endpoint for private connections. knownContactPubsFn (can be nil as a
// function pointer only if the caller doesn't want to enforce mutuality —
// see appCtx.knownContactPubs) returns the Ed25519 pubkeys of all known
// contacts, read on every knock — enables mandatory mutuality on POST
// /knock (Briar-style model, pre-decryption filter via KnockDHTag).
//
// ServerHello's signature uses the IdentityKey-per-relationship known from
// the invite bootstrap (RoomRegistry.LookupSecret), never a global identity
// distributed on request.
// mlkemDecap is the durable ML-KEM-768 decapsulation key paired with
// identityPriv (always rotates in the same event as the Ed25519 identity —
// see Keystore.MLKEMKey) — used by handleKnock to decrypt hybrid knocks. A
// fixed value, not a getter: like identityPriv, a rotation spawns a NEW
// listener/RunOnListener (new hidden service), it doesn't modify the one
// already running.
func RunOnListener(ctx context.Context, ln net.Listener, registry *RoomRegistry,
	identityPriv ed25519.PrivateKey, mlkemDecap *mlkem.DecapsulationKey768,
	knockCh chan<- shared.KnockPayload,
	knownContactPubsFn func() [][]byte, cfg ServerConfig) error {
	app := &appCtx{
		registry:            registry,
		limiter:             NewRateLimiter(time.Minute, 10),
		identityPriv:        identityPriv,
		mlkemDecap:          mlkemDecap,
		knockCh:             knockCh,
		knownContactPubs:    knownContactPubsFn,
		pingInterval:        cfg.ping(),
		cleanupInterval:     cfg.cleanup(),
		sessionStaleTimeout: cfg.sessionStale(),
		silenced:            cfg.Silenced,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/chat", app.handleWS)
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("POST /knock", app.handleKnock)
	mux.HandleFunc("POST "+shared.DeviceSyncPath, app.handleDeviceSync)

	go func() {
		ticker := time.NewTicker(app.cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			app.limiter.Cleanup()
			app.registry.CleanupStaleSessions(app.sessionStaleTimeout)
		}
	}()

	// Retry/kick of the room's reliable delivery (roomDelivery) — an
	// independent, tighter cadence than cleanupInterval (20s initial
	// backoff, same threshold already used client-side for the direct
	// relationship), doesn't reuse the ticker above: that one stays tied to
	// a minutes-scale interval (default 5m), too sparse for a retry meant
	// to run in seconds.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app.registry.RetryDelivery()
			}
		}
	}()

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second, // margin for slow Tor circuits
		WriteTimeout:      0,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// notify shutdown on all active rooms (only those with at least one
		// successful connection — the others don't have a state/hub created yet)
		app.registry.mu.RLock()
		for _, entry := range app.registry.rooms {
			if entry.state != nil {
				entry.state.hub.Broadcast(shutCtx, wsServerShutdown{Type: "server_shutdown"}, "")
			}
		}
		app.registry.mu.RUnlock()
		return srv.Shutdown(shutCtx)
	}
}
