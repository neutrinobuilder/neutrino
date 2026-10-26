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

package tornode

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/webtunnel"
)

// ptTransports lists ONLY the supported pluggable transports,
// deliberately NOT the lyrebird/transports registry package (the one
// with Init()/Get()): that package unconditionally imports Snowflake
// too (the entire pion/webrtc + AWS SDK v2 dependency tree) and Meeklite
// (utls), even though only obfs4/webtunnel are needed, verified with
// "go list -deps": importing only lyrebird/transports/obfs4 (zero heavy
// dependencies) and .../webtunnel (adds only utls, no AWS/webrtc) avoids
// nearly all the bloat. Consistent with bridge_default="obfs4"/
// bridge_fallback="webtunnel" (internal/config), the only two
// transports the project exposes.
var ptTransports = map[string]base.Transport{
	"obfs4":     &obfs4.Transport{},
	"webtunnel": webtunnel.Transport,
}

// ptClient starts pluggable transports (obfs4, webtunnel, ...)
// IN-PROCESS, in the same Go binary as Neutrino, no separate lyrebird
// binary to cross-compile/bundle/run. For each requested transport it
// opens a local SOCKS listener (goptlib): Tor itself connects to it as
// a SOCKS client in "unmanaged" mode (torrc "ClientTransportPlugin
// <name> socks5 <addr>", see torrc(5)), encoding the bridge's
// destination and arguments (cert=..., iat-mode=...) in the SOCKS
// request exactly as it would with a lyrebird launched in "exec" mode,
// goptlib decodes them into SocksRequest.Args, the lyrebird library
// does the real handshake toward the remote bridge. Same mechanism and
// same dependencies (both MIT/BSD, pure Go) used by Orbot via
// github.com/tladesignz/IPtProxy, reimplemented minimally here (only
// the transports needed, no Snowflake/DNSTT) instead of importing the
// entire library.
type ptClient struct {
	mu        sync.Mutex
	stateDir  string
	cleanup   func()
	listeners map[string]*pt.SocksListener
	shutdown  map[string]chan struct{}
}

// newPTClient prepares a dedicated temporary state directory (required
// by the ClientFactory API, not used by stateless client transports
// like obfs4/webtunnel except for possible internal logging).
func newPTClient() (*ptClient, error) {
	dir, err := os.MkdirTemp("", "neutrino-pt-*")
	if err != nil {
		return nil, fmt.Errorf("pluggable transports state directory: %w", err)
	}
	return &ptClient{
		stateDir:  dir,
		cleanup:   func() { os.RemoveAll(dir) },
		listeners: make(map[string]*pt.SocksListener),
		shutdown:  make(map[string]chan struct{}),
	}, nil
}

// Start starts (if not already active) the transport name as a local
// SOCKS listener and returns its "host:port" address for use in the
// torrc line "ClientTransportPlugin <name> socks5 <addr>".
func (c *ptClient) Start(name string) (addr string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ln, ok := c.listeners[name]; ok {
		return ln.Addr().String(), nil
	}
	t, ok := ptTransports[name]
	if !ok {
		return "", fmt.Errorf("unknown transport: %q", name)
	}
	f, err := t.ClientFactory(c.stateDir)
	if err != nil {
		return "", fmt.Errorf("initializing transport %q: %w", name, err)
	}
	ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("local SOCKS listener for %q: %w", name, err)
	}
	shutdown := make(chan struct{})
	c.listeners[name] = ln
	c.shutdown[name] = shutdown
	go ptAcceptLoop(f, ln, shutdown)
	return ln.Addr().String(), nil
}

// Close stops all started transports and removes the state directory.
func (c *ptClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, ln := range c.listeners {
		_ = ln.Close()
		close(c.shutdown[name])
	}
	c.listeners = make(map[string]*pt.SocksListener)
	c.shutdown = make(map[string]chan struct{})
	if c.cleanup != nil {
		c.cleanup()
	}
}

// ptAcceptLoop accepts incoming SOCKS connections from Tor (one for
// each connection attempt to the bridge) until shutdown is closed.
func ptAcceptLoop(f base.ClientFactory, ln *pt.SocksListener, shutdown chan struct{}) {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go ptHandleConn(f, conn, shutdown)
	}
}

// ptHandleConn performs the pluggable transport handshake toward the
// real bridge (f.Dial, direct connection, no bridge behind another
// proxy) and then forwards bytes in both directions until close or shutdown.
func ptHandleConn(f base.ClientFactory, conn *pt.SocksConn, shutdown chan struct{}) {
	defer conn.Close()

	args, err := f.ParseArgs(&conn.Req.Args)
	if err != nil {
		_ = conn.Reject()
		return
	}
	remote, err := f.Dial("tcp", conn.Req.Target, net.Dial, args)
	if err != nil {
		_ = conn.Reject()
		return
	}
	defer remote.Close()
	if err := conn.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0}); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, remote)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(remote, conn)
		done <- struct{}{}
	}()
	select {
	case <-shutdown:
	case <-done:
	}
}
