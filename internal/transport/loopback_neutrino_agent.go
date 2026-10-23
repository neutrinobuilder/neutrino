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

package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"neutrino/internal/shared"
)

// KindLoopback runs every instance on the same host without any
// anonymity network: a "hidden service" is a plain listener on
// 127.0.0.1, and its address (the same .onion string Tor would publish
// for that key) is resolved through a directory shared by all the
// instances of a test run — one file per published address, holding the
// listener's "127.0.0.1:port". Built only with the neutrino_agent tag,
// never part of a release.
const KindLoopback Kind = "loopback"

var loopbackDir string

// loopbackDirEnv carries the shared directory to processes spawned by an
// instance (the pod), which start without the agent's flags.
const loopbackDirEnv = "NEUTRINO_LOOPBACK_DIR"

// SetLoopbackDir sets the directory shared by every loopback instance of
// the same test run, also for processes the instance spawns. Must be
// called before Start(KindLoopback).
func SetLoopbackDir(dir string) {
	loopbackDir = dir
	_ = os.Setenv(loopbackDirEnv, dir)
}

func init() {
	extraKinds[KindLoopback] = startLoopback
}

type loopbackTransport struct {
	dir   string
	logCh chan string

	mu        sync.Mutex
	published []string
}

func startLoopback(ctx context.Context, cfg StartConfig) (Transport, error) {
	if loopbackDir == "" {
		loopbackDir = os.Getenv(loopbackDirEnv)
	}
	if loopbackDir == "" {
		return nil, errors.New("loopback: shared directory not set")
	}
	if err := os.MkdirAll(loopbackDir, 0o700); err != nil {
		return nil, fmt.Errorf("loopback: %w", err)
	}
	if cfg.OnProgress != nil {
		cfg.OnProgress(100)
	}
	return &loopbackTransport{dir: loopbackDir, logCh: make(chan string)}, nil
}

// entryPath maps an address to its file in the shared directory,
// rejecting anything that isn't a single plain path element.
func (t *loopbackTransport) entryPath(addr string) (string, error) {
	if addr == "" || addr != filepath.Base(addr) || strings.HasPrefix(addr, ".") {
		return "", fmt.Errorf("loopback: invalid address %q", addr)
	}
	return filepath.Join(t.dir, addr), nil
}

func (t *loopbackTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	path, err := t.entryPath(host)
	if err != nil {
		return nil, err
	}
	local, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loopback: %s unreachable: %w", host, err)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, strings.TrimSpace(string(local)))
}

func (t *loopbackTransport) DialerForToken(ctx context.Context, token string) (func(context.Context, string, string) (net.Conn, error), error) {
	return t.DialContext, nil
}

func (t *loopbackTransport) AddHiddenService(ctx context.Context, priv ed25519.PrivateKey) (net.Listener, string, string, error) {
	addr := shared.OnionAddressFromPub(priv.Public().(ed25519.PublicKey))
	path, err := t.entryPath(addr)
	if err != nil {
		return nil, "", "", err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", fmt.Errorf("loopback: %w", err)
	}
	localAddr := ln.Addr().String()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(localAddr), 0o600); err != nil {
		ln.Close()
		return nil, "", "", fmt.Errorf("loopback: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		ln.Close()
		return nil, "", "", fmt.Errorf("loopback: %w", err)
	}
	t.mu.Lock()
	t.published = append(t.published, path)
	t.mu.Unlock()
	return ln, addr, localAddr, nil
}

func (t *loopbackTransport) HasCircuits() bool { return true }

func (t *loopbackTransport) ProxyAddr() string { return "" }

func (t *loopbackTransport) LogCh() <-chan string { return t.logCh }

// Close withdraws every address this instance published, so the
// remaining instances see it as offline.
func (t *loopbackTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.published {
		_ = os.Remove(p)
	}
	t.published = nil
	return nil
}
