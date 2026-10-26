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
	"net"

	"neutrino/internal/tornode"
)

// torTransport adapts *tornode.Node to the Transport interface.
type torTransport struct {
	node *tornode.Node
}

func startTor(ctx context.Context, cfg StartConfig) (Transport, error) {
	// Retries the bridge fallback only when there are really two
	// distinct bridge sets to try, a Bridges with no BridgesFallback
	// (or no bridges at all) takes the single-attempt path.
	if cfg.Bridges != nil && len(cfg.Bridges.Lines) > 0 && cfg.BridgesFallback != nil && len(cfg.BridgesFallback.Lines) > 0 {
		timeout := cfg.BridgeBootstrapTimeout
		if timeout <= 0 {
			timeout = tornode.DefaultBridgeBootstrapTimeout
		}
		node, err := tornode.StartTorBridges(ctx, tornode.StartConfig{OnProgress: cfg.OnProgress}, cfg.Bridges, cfg.BridgesFallback, timeout, cfg.OnBridgeFallback)
		if err != nil {
			return nil, err
		}
		return &torTransport{node: node}, nil
	}
	node, err := tornode.StartTor(ctx, tornode.StartConfig{
		OnProgress: cfg.OnProgress,
		Bridges:    cfg.Bridges,
	})
	if err != nil {
		return nil, err
	}
	return &torTransport{node: node}, nil
}

func (t *torTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.node.DialContext(ctx, network, addr)
}

func (t *torTransport) DialerForToken(ctx context.Context, token string) (func(context.Context, string, string) (net.Conn, error), error) {
	return t.node.DialerForToken(ctx, token)
}

func (t *torTransport) AddHiddenService(ctx context.Context, priv ed25519.PrivateKey) (net.Listener, string, string, error) {
	return t.node.AddHiddenService(ctx, priv)
}

func (t *torTransport) HasCircuits() bool {
	return t.node.HasCircuits()
}

// ProxyAddr returns Tor's local SOCKS5 "host:port", or "" if it can't be
// queried right now (e.g. the control port isn't reachable), see
// BuildPodSnapshot/DialerSAM callers (cmd/pod_spawn.go), which treat ""
// the same as "no network inherited".
func (t *torTransport) ProxyAddr() string {
	addr, err := t.node.SocksAddr()
	if err != nil {
		return ""
	}
	return addr
}

func (t *torTransport) LogCh() <-chan string {
	return t.node.LogCh()
}

func (t *torTransport) Close() error {
	return t.node.Close()
}
