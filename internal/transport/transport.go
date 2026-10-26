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

// Package transport abstracts the transport network (Tor, I2P) used to
// publish one's own hidden service/destination and to dial contacts'
// ones. cmd/main.go is the only consumer: internal/client and
// internal/server remain transport-agnostic, receiving only an
// already-ready net.Listener and DialContext-shaped functions.
package transport

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"strings"
	"time"

	"neutrino/internal/tornode"
)

// Kind identifies the transport network chosen at startup (--net flag or config).
type Kind string

const (
	KindTor Kind = "tor"
	KindI2P Kind = "i2p"
)

// ParseKind normalizes a string (case-insensitive, "" = default) into a
// valid Kind, or returns an error if the value isn't recognized.
func ParseKind(s string) (Kind, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	switch norm {
	case "", string(KindTor):
		return KindTor, nil
	case string(KindI2P):
		return KindI2P, nil
	default:
		if _, ok := extraKinds[Kind(norm)]; ok {
			return Kind(norm), nil
		}
		return "", fmt.Errorf("unknown network: %q (valid values: tor, i2p)", s)
	}
}

// extraKinds holds transports registered by build-tag-gated files that
// are not part of the default build (empty here) — e.g. the loopback
// transport used by agent mode (build tag neutrino_agent).
var extraKinds = map[Kind]func(ctx context.Context, cfg StartConfig) (Transport, error){}

// Transport is the network node: publishes its own hidden
// service/destination and dials contacts' ones.
type Transport interface {
	// DialContext opens a connection to addr over this network.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)

	// DialerForToken returns a dialer with a circuit/path isolated by
	// token (used to route a file transfer separately from chat
	// traffic). If the network doesn't support isolation, the
	// implementation may return a dialer equivalent to DialContext. ctx
	// covers only the creation of the dialer/session itself (for I2P, a
	// real blocking SAM round-trip; for Tor, the local construction of
	// the dialer doesn't block on the network anyway), not the
	// connections the returned dialer will open afterward (those receive
	// their own ctx on each call, like DialContext).
	DialerForToken(ctx context.Context, token string) (func(context.Context, string, string) (net.Conn, error), error)

	// AddHiddenService publishes a hidden service for priv and returns
	// the local listener, the public address reachable by contacts
	// (e.g. "xxxx.onion"), and the local listen address.
	AddHiddenService(ctx context.Context, priv ed25519.PrivateKey) (ln net.Listener, addr string, localAddr string, err error)

	// HasCircuits reports whether the network has at least one usable circuit/path.
	HasCircuits() bool

	// ProxyAddr returns the local "host:port" this network's traffic is
	// routed through — Tor's SOCKS5 proxy, or i2pd's SAM bridge (NOT a
	// SOCKS5 proxy: see DialerSAM in i2p.go). "" if unavailable. Used
	// only to hand the pod (cmd/pod.go) a live network to inherit at
	// trigger time (BuildPodSnapshot) — nothing else in this codebase
	// needs the raw address, every other caller goes through DialContext/
	// DialerForToken instead.
	ProxyAddr() string

	// LogCh returns the network node/process's log channel.
	LogCh() <-chan string

	// Close stops the network node and releases its resources.
	Close() error
}

// StartConfig is the startup configuration, common to every transport.
type StartConfig struct {
	// OnProgress is called on each bootstrap advancement (0-100); nil = silent.
	OnProgress func(pct int)

	// Bridges configures bridge use — Tor-specific, ignored by other
	// backends (I2P has no equivalent concept).
	Bridges *tornode.BridgeConfig

	// BridgesFallback, if not nil and Bridges is also not nil, is tried
	// (tornode.StartTorBridges) if the Bridges bootstrap doesn't reach
	// 100% within BridgeBootstrapTimeout — Tor-specific, ignored by
	// other backends, also ignored if Bridges is nil (no bridges means
	// no fallback to try).
	BridgesFallback *tornode.BridgeConfig

	// BridgeBootstrapTimeout, if zero, uses tornode.DefaultBridgeBootstrapTimeout.
	// Ignored if Bridges is nil.
	BridgeBootstrapTimeout time.Duration

	// OnBridgeFallback, if not nil, is called once if the Bridges
	// bootstrap doesn't complete in time and the attempt with
	// BridgesFallback starts — see tornode.StartTorBridges.
	OnBridgeFallback func()
}

// Start starts the transport indicated by kind and waits until it's
// ready (bootstrap complete, similar to tornode.StartTor for Tor).
func Start(ctx context.Context, kind Kind, cfg StartConfig) (Transport, error) {
	switch kind {
	case KindTor, "":
		return startTor(ctx, cfg)
	case KindI2P:
		return startI2P(ctx, cfg)
	default:
		if start, ok := extraKinds[kind]; ok {
			return start(ctx, cfg)
		}
		return nil, fmt.Errorf("unknown network: %q", kind)
	}
}
