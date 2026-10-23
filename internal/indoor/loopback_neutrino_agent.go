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

//go:build neutrino_agent

package indoor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// loopbackPrefix names the files that register each instance's discovery
// address in the shared loopback directory.
const loopbackPrefix = "indoor-"

// UseLoopback makes discovery work between instances on the same host,
// without touching the real network: each instance gets its own
// 127.77.0.N address, registered in dir, where it accepts sessions on the
// usual TCP port and receives announcements on the usual UDP port;
// announcements go by unicast to every other registered instance. The
// sessions themselves are the real protocol.
func UseLoopback(dir string) error {
	ip, err := allocLoopbackIP(dir)
	if err != nil {
		return err
	}
	_, portStr, err := net.SplitHostPort(MulticastAddr)
	if err != nil {
		return err
	}
	announcePort, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	listenSession = func() (net.Listener, error) {
		return net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(TCPPort)))
	}
	openAnnounce = func() (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: announcePort})
	}
	announceTargets = func() []*net.UDPAddr {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var out []*net.UDPAddr
		for _, e := range entries {
			peer := net.ParseIP(strings.TrimPrefix(e.Name(), loopbackPrefix))
			if !strings.HasPrefix(e.Name(), loopbackPrefix) || peer == nil || peer.Equal(ip) {
				continue
			}
			out = append(out, &net.UDPAddr{IP: peer, Port: announcePort})
		}
		return out
	}
	return nil
}

// allocLoopbackIP reserves the first free 127.77.0.N address in dir.
func allocLoopbackIP(dir string) (net.IP, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for n := 1; n < 255; n++ {
		ip := net.IPv4(127, 77, 0, byte(n))
		f, err := os.OpenFile(filepath.Join(dir, loopbackPrefix+ip.String()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return ip.To4(), nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("indoor: no free loopback address in %s", dir)
}
