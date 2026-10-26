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

package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"neutrino/internal/i18n"
	"neutrino/internal/i2pnode"
	"neutrino/internal/shared"
)

// i2pTransport implements Transport on top of a local i2pd process
// (managed by internal/i2pnode, embedded on linux/amd64, a system
// daemon elsewhere), spoken via the SAM API (a text bridge, a
// line-based protocol over TCP). This file deals only with the SAM
// protocol (sessions, destinations, dial/accept) and the Transport
// interface; the i2pd process's lifecycle lives entirely in
// i2pnode.Node.
type i2pTransport struct {
	node *i2pnode.Node
	// samBridgeAddr: node.SAMAddr(), read once at construction (never
	// changes for the i2pd process's lifetime), avoids requiring a real
	// *i2pnode.Node just to exercise the SAM protocol in this package's
	// tests (i2p_test.go), which can build an *i2pTransport by hand with
	// only this field set.
	samBridgeAddr string

	mu        sync.Mutex
	sessions  []net.Conn       // control connections that keep open SAM sessions alive
	hostSess  string           // "host" session ID (created by AddHiddenService), "" if none
	cliSess   string           // session ID used for outbound dials when there's no host yet
	listeners []*fanInListener // one per AddHiddenService, closed by Close()
	// lastDialFailed: outcome of the LAST STREAM CONNECT observed on
	// DialContext (never touched by DialerForToken, a separate isolated
	// session, see HasCircuits). SAM v3 exposes no tunnel status query
	// equivalent to Tor's control port "GETINFO circuit-status" (i2pd
	// only has it on I2PControl, a separate JSON-RPC service not
	// integrated here), an actual successful/failed dial remains the
	// most direct signal available without building that integration
	// from scratch.
	lastDialFailed bool
}

func startI2P(ctx context.Context, cfg StartConfig) (Transport, error) {
	if cfg.OnProgress != nil {
		cfg.OnProgress(0)
	}
	// i2pd exposes no granular progress signal like Tor's "Bootstrapped
	// N%": the SAM bridge becomes usable a few seconds after startup,
	// regardless of the network's full bootstrap (which continues in the
	// background). OnProgress here is therefore just 0 → 100, not
	// incremental.
	node, err := i2pnode.StartI2p(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.OnProgress != nil {
		cfg.OnProgress(100)
	}
	return &i2pTransport{node: node, samBridgeAddr: node.SAMAddr()}, nil
}

func (t *i2pTransport) samAddr() string { return t.samBridgeAddr }

func (t *i2pTransport) trackConn(c net.Conn) {
	t.mu.Lock()
	t.sessions = append(t.sessions, c)
	t.mu.Unlock()
}

// AddHiddenService publishes the I2P destination derived from priv (see
// shared.I2PDestinationPriv) and returns a net.Listener that accepts
// both inbound remote peers (STREAM ACCEPT via SAM, see sam.go) and the
// TUI's local self-connect: samListener is purely virtual (no OS port
// behind it), so the third returned string (localAddr, used by
// cmd/main.go to dial itself directly over TCP) can't be t.samAddr(),
// that's i2pd's SAM control port, it doesn't speak HTTP/WS, and dialing
// it causes an EOF in the handshake. Instead a real local TCP
// net.Listener is created (the same role as bine's svc.LocalListener for
// Tor) and combined with samListener in a fanInListener: both sources
// feed the same server.RunOnListener, so local self-connect and remote
// peers via I2P end up in the same registry/hub.
func (t *i2pTransport) AddHiddenService(ctx context.Context, priv ed25519.PrivateKey) (net.Listener, string, string, error) {
	privBlob, err := shared.I2PDestinationPriv(priv)
	if err != nil {
		return nil, "", "", err
	}
	addr, err := shared.I2PAddress(priv)
	if err != nil {
		return nil, "", "", err
	}
	destB64 := i2pB64Encode(privBlob)
	pub := priv.Public().(ed25519.PublicKey)
	sessionID := fmt.Sprintf("neutrino-host-%x", []byte(pub[:8]))

	conn, err := samSessionCreate(ctx, t.samAddr(), sessionID, destB64)
	if err != nil {
		return nil, "", "", err
	}
	t.trackConn(conn)

	t.mu.Lock()
	t.hostSess = sessionID
	t.mu.Unlock()

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", err
	}
	sam := newSAMListener(t.samAddr(), sessionID, samAddr(addr))
	ln := newFanInListener(local, sam)

	t.mu.Lock()
	t.listeners = append(t.listeners, ln)
	t.mu.Unlock()

	return ln, addr, local.Addr().String(), nil
}

// DialContext opens a connection to addr (interpreted as "host[:port]",
// the port is ignored: I2P routes by destination, not by port). host can
// be a complete public destination in base64 (the recommended case: the
// caller computes shared.I2PDestinationPub(contact) and encodes it with
// I2PB64Encode) or a .b32.i2p address/hostname, resolved via SAM "NAMING
// LOOKUP" (requires the destination to already be known to the local
// NetDb).
func (t *i2pTransport) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	sessionID, err := t.dialSessionID(ctx)
	if err != nil {
		return nil, err
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	dest, err := t.resolveDestination(ctx, host)
	if err != nil {
		return nil, err
	}
	conn, err := samDial(ctx, t.samAddr(), sessionID, dest)
	// Only the outcome of the actual STREAM CONNECT updates the health
	// signal (see HasCircuits), a failure in dialSessionID/
	// resolveDestination above (NAMING LOOKUP, typically specific to the
	// single peer/destination) doesn't imply I2P as a whole is down, so
	// it doesn't touch it.
	t.mu.Lock()
	t.lastDialFailed = err != nil
	t.mu.Unlock()
	return conn, err
}

// dialSessionID returns the session to use for outbound dials: the
// "host" one if already created (AddHiddenService already called),
// otherwise a dedicated client session, created on the fly the first
// time.
func (t *i2pTransport) dialSessionID(ctx context.Context) (string, error) {
	t.mu.Lock()
	if t.hostSess != "" {
		id := t.hostSess
		t.mu.Unlock()
		return id, nil
	}
	if t.cliSess != "" {
		id := t.cliSess
		t.mu.Unlock()
		return id, nil
	}
	t.mu.Unlock()

	const id = "neutrino-cli"
	conn, err := samSessionCreate(ctx, t.samAddr(), id, "TRANSIENT")
	if err != nil {
		return "", err
	}
	t.trackConn(conn)
	t.mu.Lock()
	if t.hostSess == "" && t.cliSess == "" {
		t.cliSess = id
	}
	t.mu.Unlock()
	return id, nil
}

// DialerForToken creates a dedicated SAM session (ephemeral destination)
// for token, giving real isolation (separate I2P tunnels) between chat
// traffic and a file transfer, analogous to Tor's DialerForToken. ctx
// covers only this creation (samSessionCreate, a real blocking SAM
// round-trip, unlike Tor, where building the dialer does no network
// I/O), so the caller's timeout/cancellation is honored here too.
func (t *i2pTransport) DialerForToken(ctx context.Context, token string) (func(context.Context, string, string) (net.Conn, error), error) {
	sessionID := "neutrino-tok-" + sanitizeSAMID(token)
	conn, err := samSessionCreate(ctx, t.samAddr(), sessionID, "TRANSIENT")
	if err != nil {
		return nil, err
	}
	t.trackConn(conn)
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		dest, err := t.resolveDestination(ctx, host)
		if err != nil {
			return nil, err
		}
		return samDial(ctx, t.samAddr(), sessionID, dest)
	}, nil
}

// resolveDestination returns the base64 blob to pass to STREAM CONNECT:
// if host is already a complete destination it's used directly,
// otherwise it tries a NAMING LOOKUP (for .b32.i2p addresses or
// registered hostnames).
func (t *i2pTransport) resolveDestination(ctx context.Context, host string) (string, error) {
	return resolveSAMDestination(ctx, t.samAddr(), host)
}

// resolveSAMDestination is the free-standing form of
// i2pTransport.resolveDestination, taking samAddr directly instead of
// through a live *i2pTransport, needed by DialerSAM, whose caller (the
// pod, see cmd/pod.go) never builds a full i2pTransport.
func resolveSAMDestination(ctx context.Context, samAddr, host string) (string, error) {
	if looksLikeI2PDestinationBlob(host) {
		return host, nil
	}
	conn, rw, err := samDialRaw(ctx, samAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	fmt.Fprintf(rw, "NAMING LOOKUP NAME=%s\n", host)
	if err := rw.Flush(); err != nil {
		return "", err
	}
	line, err := rw.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.Contains(line, "RESULT=OK") {
		return "", errors.New(i18n.T("transport.err_naming_lookup", host, strings.TrimSpace(line)))
	}
	_, value, ok := strings.Cut(line, "VALUE=")
	if !ok {
		return "", errors.New(i18n.T("transport.err_naming_lookup_no_value", strings.TrimSpace(line)))
	}
	if j := strings.IndexAny(value, " \r\n"); j >= 0 {
		value = value[:j]
	}
	return value, nil
}

// DialerSAM opens a single transient SAM session against samAddr and
// returns a DialContext-shaped function that dials I2P destinations over
// it, reusing the same session for every call, the SAM equivalent of
// tornode.Node.DialContext's single reused Tor dialer. Meant for a
// short-lived one-shot process (the pod, see cmd/pod.go) that never
// becomes a full Transport: the session's control connection is
// deliberately never closed here, since the process exits (and the OS
// reclaims it) within its own short delivery budget.
func DialerSAM(ctx context.Context, samAddr string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	const sessionID = "neutrino-pod"
	if _, err := samSessionCreate(ctx, samAddr, sessionID, "TRANSIENT"); err != nil {
		return nil, err
	}
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		dest, err := resolveSAMDestination(ctx, samAddr, host)
		if err != nil {
			return nil, err
		}
		return samDial(ctx, samAddr, sessionID, dest)
	}, nil
}

// looksLikeI2PDestinationBlob heuristically distinguishes a complete
// public destination (base64 of 391+ bytes, ≥ ~520 characters) from a
// short address (.b32.i2p, ~60 characters, or a hostname). The margin is
// wide, character-level precision isn't needed.
func looksLikeI2PDestinationBlob(s string) bool {
	return len(s) > 200
}

// HasCircuits reports whether I2P currently appears to have working
// connectivity, unlike the Tor equivalent (tornode.go, which actually
// queries "GETINFO circuit-status" on the control port), SAM v3 exposes
// no tunnel status query (only I2PControl, a separate JSON-RPC service
// not integrated here). A session having ever been created
// (hostSess/cliSess non-empty) isn't enough by itself: it also factors
// in the outcome of the last observed dial (lastDialFailed, updated by
// DialContext), a session exists but the most recent dial failed means
// no longer "healthy". This remains a REACTIVE signal, not a proactive
// check like Tor's: if no dial has happened recently, it only reflects
// the last known outcome, not the CURRENT state of the tunnels, an
// intrinsic limit of SAM v3 lacking a direct query, not resolvable
// without I2PControl.
func (t *i2pTransport) HasCircuits() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return (t.hostSess != "" || t.cliSess != "") && !t.lastDialFailed
}

// ProxyAddr returns i2pd's local SAM bridge "host:port", NOT a SOCKS5
// proxy (see DialerSAM above). Same role as torTransport.ProxyAddr for
// the Transport interface.
func (t *i2pTransport) ProxyAddr() string { return t.samAddr() }

func (t *i2pTransport) LogCh() <-chan string { return t.node.LogCh() }

func (t *i2pTransport) Close() error {
	t.mu.Lock()
	sessions := t.sessions
	t.sessions = nil
	listeners := t.listeners
	t.listeners = nil
	t.mu.Unlock()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	for _, c := range sessions {
		_ = c.Close()
	}
	return t.node.Close()
}

// i2pB64Encode encodes to base64 using the alphabet I2P/SAM uses
// ('-' instead of '+', '~' instead of '/', padding not removed).
func i2pB64Encode(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	return strings.NewReplacer("+", "-", "/", "~").Replace(s)
}

func sanitizeSAMID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	return sb.String()
}
