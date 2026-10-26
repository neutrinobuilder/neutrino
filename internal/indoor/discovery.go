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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// sessionResult is the outcome of ONE completed TCP session (success or
// failure), RunSync collects the first successful outcome, but also
// drains (without blocking) failed ones, to keep listening.
type sessionResult struct {
	payload SyncPayload
	err     error
}

// Event is a RunSync progress event, reported via onEvent to show it in
// Console, never blocking for the caller (onEvent runs on the same
// goroutine that emits it, so it must stay fast).
type Event struct {
	Kind   string // "listening" | "announcing" | "peer_found" | "session_failed" | "session_ok"
	Detail string
}

// RunSync runs an "indoor" synchronization window for the given identity
// (identityPriv) and payload (myPayload, typically the contact list plus
// its own DeviceRecord): listens for incoming TCP connections on TCPPort,
// periodically announces its own IdentityHash on the multicast group, and
// starts a session toward any matching announcement received. Returns on
// the FIRST successful exchange (the caller does MergeContacts/
// AppendKnownDevice on the received payload), or when ctx is cancelled or
// SyncWindow expires, whichever happens first. onEvent (optional)
// receives an Event for every significant step, for progress reporting in
// Console.
func RunSync(ctx context.Context, identityPriv ed25519.PrivateKey, myPayload SyncPayload, round TombstoneRound, onEvent func(Event)) (SyncPayload, error) {
	if len(identityPriv) != ed25519.PrivateKeySize {
		return SyncPayload{}, errors.New("indoor: missing or invalid identity key")
	}
	emit := func(kind, detail string) {
		if onEvent != nil {
			onEvent(Event{Kind: kind, Detail: detail})
		}
	}

	identityPub := identityPriv.Public().(ed25519.PublicKey)
	myHash := IdentityHash(identityPub)
	instanceID := make([]byte, 8)
	if _, err := rand.Read(instanceID); err != nil {
		return SyncPayload{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, SyncWindow)
	defer cancel()

	results := make(chan sessionResult, 8)
	var wg sync.WaitGroup

	// ── TCP listener (responder role: accepts whoever connects to us after
	// seeing our announcement) ──────────────────────────────────────
	ln, err := listenSession()
	if err != nil {
		return SyncPayload{}, err
	}
	defer ln.Close()
	emit("listening", ln.Addr().String())

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed (ctx done, see below) or a fatal error
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				payload, err := RunSession(conn, 15*time.Second, identityPriv, myPayload, false, round)
				select {
				case results <- sessionResult{payload: payload, err: err}:
				case <-ctx.Done():
				}
			}()
		}
	}()
	// Closes the listener when ctx is done, unblocking Accept().
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// ── multicast discovery (periodic announce + listen) ────────────────
	udpConn, err := openAnnounce()
	if err != nil {
		return SyncPayload{}, err
	}
	defer udpConn.Close()

	seenAddrs := make(map[string]bool) // avoids multiple TCP attempts to the same address within the same window
	var seenMu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := udpConn.ReadFromUDP(buf)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				continue // read timeout, normal, re-check ctx and retry
			}
			pkt, err := DecodeAnnounce(buf[:n])
			if err != nil || pkt.Version != ProtocolVersion {
				continue
			}
			if bytes.Equal(pkt.InstanceID, instanceID) {
				continue // our own announcement (multicast loopback)
			}
			if !bytes.Equal(pkt.IdentityHash, myHash) {
				continue // different identity, not for us
			}
			key := addr.IP.String()
			seenMu.Lock()
			already := seenAddrs[key]
			if !already {
				seenAddrs[key] = true
			}
			seenMu.Unlock()
			if already {
				continue
			}
			emit("peer_found", key)
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(TCPPort)), 5*time.Second)
				if err != nil {
					select {
					case results <- sessionResult{err: err}:
					case <-ctx.Done():
					}
					return
				}
				defer conn.Close()
				payload, err := RunSession(conn, 15*time.Second, identityPriv, myPayload, true, round)
				select {
				case results <- sessionResult{payload: payload, err: err}:
				case <-ctx.Done():
				}
			}(key)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		announcePkt := AnnouncePacket{Version: ProtocolVersion, IdentityHash: myHash, InstanceID: instanceID}
		raw, err := EncodeAnnounce(announcePkt)
		if err != nil {
			return
		}
		ticker := time.NewTicker(AnnounceInterval)
		defer ticker.Stop()
		emit("announcing", "")
		for {
			for _, dst := range announceTargets() {
				_, _ = udpConn.WriteToUDP(raw, dst)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// ── waiting for the first usable outcome ───────────────────────────────────────
	var final SyncPayload
	var finalErr error = errors.New("indoor: no peer found within the sync window")
	done := false
	for !done {
		select {
		case r := <-results:
			if r.err != nil {
				emit("session_failed", r.err.Error())
				continue
			}
			emit("session_ok", "")
			final, finalErr = r.payload, nil
			done = true
		case <-ctx.Done():
			done = true
		}
	}
	cancel()
	wg.Wait()
	return final, finalErr
}

// listenSession, openAnnounce and announceTargets are the network side of
// discovery: where peers' sessions are accepted, the socket announcements
// go through, and where they are sent. On a real network: the fixed TCP
// port on every interface, and the multicast group in both directions.
var (
	listenSession = func() (net.Listener, error) {
		return net.Listen("tcp", ":"+strconv.Itoa(TCPPort))
	}
	openAnnounce    = openMulticast
	announceTargets = func() []*net.UDPAddr {
		dst, err := net.ResolveUDPAddr("udp4", MulticastAddr)
		if err != nil {
			return nil
		}
		return []*net.UDPAddr{dst}
	}
)

// openMulticast opens a UDP socket joined to the discovery multicast
// group, usable both to receive (ReadFromUDP) and send (WriteToUDP)
// announcements, the same *net.UDPConn for both directions. nil as the
// interface joins the group on every available interface.
func openMulticast() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", MulticastAddr)
	if err != nil {
		return nil, err
	}
	return net.ListenMulticastUDP("udp4", nil, addr)
}
