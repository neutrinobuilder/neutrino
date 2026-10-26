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
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// watchCtxDeadline arms a watcher goroutine that, if ctx expires/is
// canceled before stop() is called, forces conn.SetDeadline into the
// past, immediately unblocking an in-flight Read/Write (or a
// subsequent one). Needed because the SAM v3 protocol below is plain
// text over a bufio.ReadWriter (rw.ReadString), which otherwise has no
// way to honor ctx after the initial TCP connect (that part is already
// honored by net.Dialer.DialContext, in samDialRaw), a slow or stuck
// SAM bridge (i2pd) would otherwise leave the caller hanging
// indefinitely, ignoring any timeout set on ctx (e.g. the 90s per
// attempt of Client.ConnectWithRetry). The caller MUST `defer stop()`
// right after arming it: if ctx never expires during the covered
// window, no deadline is ever touched (safe for a conn the caller
// intends to reuse beyond this single call, e.g. the SAM session's
// control connection); if instead it expires BEFORE stop() is called,
// the caller itself interprets the resulting read error and closes
// conn, never a "successful" return with a residual deadline still
// active.
func watchCtxDeadline(ctx context.Context, conn net.Conn) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

// samConn adapts a SAM STREAM connection (after the handshake) to
// net.Conn. Read goes through the bufio.Reader used for the handshake
// itself: any bytes that already arrived along with the status response
// must not be lost by then reading from the raw net.Conn.
type samConn struct {
	net.Conn
	r        *bufio.Reader
	peerDest string // remote peer's base64 destination (SILENT=false), empty for outbound connections
}

func (c *samConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// samAddr implements net.Addr for an I2P address (.b32.i2p or base64 destination).
type samAddr string

func (a samAddr) Network() string { return "i2p" }
func (a samAddr) String() string  { return string(a) }

// samHello performs the HELLO handshake on a freshly opened SAM
// connection. Must be repeated on EVERY new connection to the SAM
// bridge: in SAM v3's "stream" style, control/accept/connect are
// distinct TCP sockets.
func samHello(rw *bufio.ReadWriter) error {
	if _, err := rw.WriteString("HELLO VERSION MIN=3.0 MAX=3.3\n"); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}
	line, err := rw.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "RESULT=OK") {
		return fmt.Errorf("sam: HELLO failed: %s", strings.TrimSpace(line))
	}
	return nil
}

// samDialRaw opens a new TCP connection to the SAM bridge and performs HELLO.
func samDialRaw(ctx context.Context, samAddr string) (net.Conn, *bufio.ReadWriter, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", samAddr)
	if err != nil {
		return nil, nil, err
	}
	stop := watchCtxDeadline(ctx, conn)
	defer stop()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := samHello(rw); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

// samSessionCreate opens a dedicated control connection and creates a
// SAM STYLE=STREAM session with the given id and destination. The
// connection must be kept open for the session's whole lifetime: closing
// it terminates the session on the i2pd side. destination is
// "TRANSIENT" for an ephemeral destination, or the base64 blob (I2P
// alphabet) of a private destination, see shared.I2PDestinationPriv.
func samSessionCreate(ctx context.Context, samSockAddr, sessionID, destination string) (net.Conn, error) {
	conn, rw, err := samDialRaw(ctx, samSockAddr)
	if err != nil {
		return nil, err
	}
	stop := watchCtxDeadline(ctx, conn)
	defer stop()
	fmt.Fprintf(rw, "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s SIGNATURE_TYPE=7\n", sessionID, destination)
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	line, err := rw.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(line, "RESULT=OK") {
		conn.Close()
		return nil, fmt.Errorf("sam: SESSION CREATE failed: %s", strings.TrimSpace(line))
	}
	return conn, nil
}

// samListener implements net.Listener on top of "STREAM ACCEPT": each
// Accept opens a new dedicated control connection (required by SAM for
// every inbound stream) and waits for a peer on the given session.
type samListener struct {
	samSockAddr string
	sessionID   string
	addr        net.Addr

	ctx    context.Context
	cancel context.CancelFunc
}

func newSAMListener(samSockAddr, sessionID string, addr net.Addr) *samListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &samListener{samSockAddr: samSockAddr, sessionID: sessionID, addr: addr, ctx: ctx, cancel: cancel}
}

func (l *samListener) Accept() (net.Conn, error) {
	for {
		if l.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		conn, rw, err := samDialRaw(l.ctx, l.samSockAddr)
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		// l.ctx, not a per-call ctx: Accept() implements net.Listener, no
		// ctx parameter is available, l.ctx is still the correct lifetime
		// context to honor here, canceled by Close() (below): without this
		// watcher, a Close() during an in-flight STREAM ACCEPT would leave
		// Accept() blocked forever, ctx canceled or not.
		stop := watchCtxDeadline(l.ctx, conn)
		fmt.Fprintf(rw, "STREAM ACCEPT ID=%s SILENT=false\n", l.sessionID)
		if err := rw.Flush(); err != nil {
			stop()
			conn.Close()
			continue
		}
		status, err := rw.ReadString('\n')
		if err != nil {
			stop()
			conn.Close()
			continue
		}
		if !strings.Contains(status, "RESULT=OK") {
			stop()
			conn.Close()
			// Session closed (Close()) or unrecoverable error on the i2pd side: propagate.
			return nil, fmt.Errorf("sam: STREAM ACCEPT failed: %s", strings.TrimSpace(status))
		}
		peerDest, err := rw.ReadString('\n') // peer's destination header (SILENT=false)
		if err != nil {
			stop()
			conn.Close()
			continue
		}
		stop()
		return &samConn{Conn: conn, r: rw.Reader, peerDest: strings.TrimSpace(peerDest)}, nil
	}
}

func (l *samListener) Close() error {
	l.cancel()
	return nil
}

func (l *samListener) Addr() net.Addr { return l.addr }

// fanInListener combines a real local TCP net.Listener (the TUI's
// self-connect, the same role as bine's svc.LocalListener for Tor) and a
// samListener (I2P streams from remote peers) into a single
// net.Listener: both sources feed the same server.RunOnListener, so
// local self-connect and remote peers via I2P end up in the same
// registry/hub.
type fanInListener struct {
	local net.Listener
	sam   *samListener

	connCh    chan net.Conn
	errCh     chan error
	done      chan struct{}
	closeOnce sync.Once
}

func newFanInListener(local net.Listener, sam *samListener) *fanInListener {
	l := &fanInListener{
		local:  local,
		sam:    sam,
		connCh: make(chan net.Conn),
		errCh:  make(chan error, 2),
		done:   make(chan struct{}),
	}
	go l.acceptLoop(local)
	go l.acceptLoop(sam)
	return l
}

func (l *fanInListener) acceptLoop(src net.Listener) {
	for {
		conn, err := src.Accept()
		if err != nil {
			select {
			case l.errCh <- err:
			case <-l.done:
			}
			return
		}
		select {
		case l.connCh <- conn:
		case <-l.done:
			conn.Close()
			return
		}
	}
}

func (l *fanInListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops both sources: closing local/sam unblocks the two
// acceptLoops' Accept() calls, which then exit on their own seeing
// l.done closed.
func (l *fanInListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	errLocal := l.local.Close()
	errSAM := l.sam.Close()
	if errLocal != nil {
		return errLocal
	}
	return errSAM
}

func (l *fanInListener) Addr() net.Addr { return l.local.Addr() }

// samDial opens an outbound connection to destBase64 (public destination
// in base64, I2P alphabet) using the sessionID session.
func samDial(ctx context.Context, samSockAddr, sessionID, destBase64 string) (net.Conn, error) {
	conn, rw, err := samDialRaw(ctx, samSockAddr)
	if err != nil {
		return nil, err
	}
	stop := watchCtxDeadline(ctx, conn)
	defer stop()
	fmt.Fprintf(rw, "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n", sessionID, destBase64)
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	line, err := rw.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(line, "RESULT=OK") {
		conn.Close()
		return nil, fmt.Errorf("sam: STREAM CONNECT failed: %s", strings.TrimSpace(line))
	}
	return &samConn{Conn: conn, r: rw.Reader}, nil
}
