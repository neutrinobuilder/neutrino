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

// Package tornode manages the Tor node embedded in the binary.
// On linux/amd64, linux/arm64, darwin/amd64 and darwin/arm64 the tor binary is embedded
// directly (go:embed); on other platforms the system `tor` daemon is used
// as a fallback. On macOS the embedded tor also requires libevent.dylib alongside it
// (extracted and possibly ad-hoc signed at runtime, see extractBinary/adhocSignDarwin)
// it's not static like on linux/amd64 and linux/arm64 (e.g. Termux/Android), which
// instead must be recompiled with download_build_tor-core.sh.
//
// To update the embedded linux binary:
//
//	bash internal/tornode/download_build_tor-core.sh [arm64]   # linux: compiled static
//
// No go:generate directive here on purpose: the script targets a
// specific platform and must never be invoked automatically by a bare
// `go generate` on an unknown host.
package tornode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
	tored25519 "github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/net/proxy"

	"neutrino/internal/androidnative"
	"neutrino/internal/i18n"
)

// Node manages the Tor process and the active hidden services.
type Node struct {
	t               *tor.Tor
	mu              sync.Mutex
	svcs            []*tor.OnionService
	cleanup         func()                 // removes the tor binary extracted into a temp dir (if embedded)
	ptc             *ptClient              // in-process pluggable transport (nil if no bridge)
	logCh           chan string            // Tor process log, one line per element
	dialer          *tor.Dialer            // shared generic dialer
	isolatedDialers map[string]*tor.Dialer // token → dialer with a dedicated circuit
}

// LogCh returns the channel the Tor process's log lines are sent on.
// The channel is buffered (2000 elements); excess lines are silently discarded.
func (n *Node) LogCh() <-chan string {
	return n.logCh
}

// BridgeConfig configures the use of Tor bridges to bypass restrictive firewalls.
// Get updated bridges at: https://bridges.torproject.org (obfs4 type)
type BridgeConfig struct {
	// Lines contains the bridge lines, one per element.
	// obfs4 format: "obfs4 <ip>:<port> <fingerprint> cert=<cert> iat-mode=0"
	// plain format: "<ip>:<port> <fingerprint>"
	// The "Bridge " prefix is optional and stripped automatically.
	Lines []string
}

// StartConfig is the optional configuration for StartTor/StartTorBridges.
type StartConfig struct {
	OnProgress func(int)     // called on every bootstrap advance (0-100); nil = silent
	Bridges    *BridgeConfig // nil = direct connection without bridges
}

// StartTor starts Tor with the full configuration, including optional
// bridge support, a single attempt, no retry: returns as soon as the
// Tor process authenticates the control port, not when bootstrap
// reaches 100% (see StartTorBridges for the wait-with-timeout and retry
// on a second bridge set). If cfg.Bridges is non-nil, the requested
// transports (obfs4/webtunnel, see ptTransports) are started in-process
// (ptclient.go) and Tor is configured to use them in "unmanaged" mode
// (ClientTransportPlugin ... socks5 <addr>), no separate lyrebird
// binary. The entire Tor process output (stdout+stderr) is redirected
// to node.LogCh() instead of os.Stdout/os.Stderr, so the terminal stays clean.
func StartTor(ctx context.Context, cfg StartConfig) (*Node, error) {
	logCh := make(chan string, 2000)
	tw := &torWriter{onProgress: cfg.OnProgress, ch: logCh}

	// Determine the tor binary path before creating the ProcessCreator.
	var exePath string
	var cleanup func()
	switch {
	case runtime.GOOS == "android":
		// The real binary (libtor.so, guardianproject/tor-android) isn't
		// go:embed, it arrives in the APK via jniLibs/<abi>/ and is
		// already executable (755) because it's extracted by the
		// PackageManager into nativeLibraryDir: no write, no chmod, no
		// cleanup to do here (stays nil).
		dir, _, err := androidnative.Resolve()
		if err != nil {
			return nil, errors.New(i18n.T("tornode.err_android_native_lib_dir", err))
		}
		path := filepath.Join(dir, "libtor.so")
		if _, err := os.Stat(path); err != nil {
			return nil, errors.New(i18n.T("tornode.err_android_tor_missing", err))
		}
		exePath = path
	case len(torBinary) > 0:
		path, cl, err := extractBinary()
		if err != nil {
			return nil, errors.New(i18n.T("tornode.err_extract_embedded", err))
		}
		exePath = path
		cleanup = cl
	default:
		exePath = "tor"
	}

	conf := &tor.StartConf{
		EnableNetwork:   true,
		NoHush:          true, // we want [notice] to parse "Bootstrapped X%"
		TempDataDirBase: os.TempDir(),
		// Custom ProcessCreator: redirects stdout/stderr to torWriter
		// instead of bine's default behavior (cmd.Stdout/Stderr = os.Stdout/Stderr).
		ProcessCreator: process.CmdCreatorFunc(func(pCtx context.Context, args ...string) (*exec.Cmd, error) {
			cmd := exec.CommandContext(pCtx, exePath, args...)
			cmd.Stdout = tw
			cmd.Stderr = tw
			return cmd, nil
		}),
	}

	var ptc *ptClient
	if cfg.Bridges != nil && len(cfg.Bridges.Lines) > 0 {
		pc, bridgeArgs, err := prepareBridgeArgs(cfg.Bridges)
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, errors.New(i18n.T("tornode.err_bridge_pt_start", err))
		}
		ptc = pc
		conf.ExtraArgs = bridgeArgs
	}

	t, err := tor.Start(ctx, conf)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		if ptc != nil {
			ptc.Close()
		}
		hint := ""
		if len(torBinary) == 0 {
			hint = i18n.T("tornode.hint_install_tor")
		}
		return nil, errors.New(i18n.T("tornode.err_start", err, hint))
	}

	return &Node{t: t, cleanup: cleanup, ptc: ptc, logCh: logCh}, nil
}

// DefaultBridgeBootstrapTimeout is how long to wait for bootstrap with a
// given bridge set to reach 100% before considering it failed and
// moving to the next set (StartTorBridges). An obfs4/webtunnel bridge
// blocked by the censor or expired never produces an explicit error
// from StartTor/tor.Start, the bootstrap simply never advances past a
// certain percentage (often 0-10%), so it must be detected by timeout,
// not by error. The value is more permissive than a plain direct
// bootstrap (inherently slower with a pluggable transport in the middle).
const DefaultBridgeBootstrapTimeout = 90 * time.Second

// StartTorBridges starts Tor using the primary bridges first; if
// bootstrap doesn't reach 100% within timeout, it closes that attempt
// and retries with fallback (if non-nil and non-empty). If the fallback
// attempt also fails (or there's no fallback), it returns the last
// attempt's error, ErrBridgeBootstrapTimeout if the timeout expired,
// StartTor's error otherwise. cfg.OnProgress, if present, is still
// invoked for every advance of BOTH attempts (the user sees the
// percentage even of an attempt later discarded); cfg.Bridges is
// ignored, bridges are given explicitly via primary/fallback, one
// attempt at a time. onFallback, if non-nil, is called once right
// before starting the fallback attempt, lets the caller notify the
// user (otherwise the bootstrap percentage would seem to reset/stall
// without explanation, being a brand-new Tor process restarting from 0%).
func StartTorBridges(ctx context.Context, cfg StartConfig, primary, fallback *BridgeConfig, timeout time.Duration, onFallback func()) (*Node, error) {
	node, err := startAndAwaitBootstrap(ctx, cfg, primary, timeout)
	if err == nil {
		return node, nil
	}
	if fallback == nil || len(fallback.Lines) == 0 {
		return nil, err
	}
	if onFallback != nil {
		onFallback()
	}
	return startAndAwaitBootstrap(ctx, cfg, fallback, timeout)
}

// ErrBridgeBootstrapTimeout indicates that bootstrap with a bridge set
// didn't reach 100% within the given timeout, not a Start error (the
// Tor process started and was closed here), but a stall.
var ErrBridgeBootstrapTimeout = errors.New("bridge bootstrap timeout")

// startAndAwaitBootstrap makes a single StartTor attempt with bridges
// set and waits (with a timeout) for OnProgress to signal 100, unlike
// StartTor alone, which returns as soon as the process authenticates
// the control port, well before bootstrap is actually complete.
func startAndAwaitBootstrap(ctx context.Context, cfg StartConfig, bridges *BridgeConfig, timeout time.Duration) (*Node, error) {
	reached100 := make(chan struct{})
	var once sync.Once
	userOnProgress := cfg.OnProgress
	attemptCfg := cfg
	attemptCfg.Bridges = bridges
	attemptCfg.OnProgress = func(pct int) {
		if userOnProgress != nil {
			userOnProgress(pct)
		}
		if pct >= 100 {
			once.Do(func() { close(reached100) })
		}
	}
	node, err := StartTor(ctx, attemptCfg)
	if err != nil {
		return nil, err
	}
	select {
	case <-reached100:
		return node, nil
	case <-time.After(timeout):
		node.Close()
		return nil, ErrBridgeBootstrapTimeout
	case <-ctx.Done():
		node.Close()
		return nil, ctx.Err()
	}
}

// prepareBridgeArgs builds the ExtraArgs for Tor with the given
// bridges. For each distinct pluggable transport name found in the
// bridge lines (e.g. "obfs4", "webtunnel", never a single hardcoded
// name: a bridge_fallback of a different type than bridge_default works
// correctly) it starts the transport in-process (ptclient.go) and adds
// the corresponding "ClientTransportPlugin <name> socks5 <addr>" line.
// Returns the *ptClient used (nil if no pluggable transport is needed)
// so the caller can close it together with the Node.
func prepareBridgeArgs(bc *BridgeConfig) (pc *ptClient, args []string, err error) {
	args = []string{"--UseBridges", "1"}

	ptNames := map[string]bool{}
	for _, line := range bc.Lines {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Bridge "), "bridge "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		args = append(args, "--Bridge", line)
		// If the first field isn't an IP:port, it's a transport name (e.g. "obfs4")
		if first := strings.Fields(line)[0]; !isIPPort(first) {
			ptNames[first] = true
		}
	}

	if len(ptNames) == 0 {
		return nil, args, nil
	}

	pc, err = newPTClient()
	if err != nil {
		return nil, nil, err
	}
	for name := range ptNames {
		addr, err := pc.Start(name)
		if err != nil {
			pc.Close()
			return nil, nil, fmt.Errorf("starting pluggable transport %q: %w", name, err)
		}
		args = append(args, "--ClientTransportPlugin", name+" socks5 "+addr)
	}
	return pc, args, nil
}

// isIPPort checks whether s is in host:port form (to distinguish an IP from a transport name).
func isIPPort(s string) bool {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// torWriter receives the Tor process's stdout/stderr, extracts the
// bootstrap percentage, and sends every line to the logCh channel for
// display in the TUI's "Tor" tab.
type torWriter struct {
	onProgress func(int)
	ch         chan<- string
	buf        []byte
	lastPct    int
}

func (w *torWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:i]), "\r")
		w.buf = w.buf[i+1:]
		if line == "" {
			continue
		}
		// Progress callback: looks for "Bootstrapped X%"
		if w.onProgress != nil {
			if idx := strings.Index(line, "Bootstrapped "); idx >= 0 {
				rest := line[idx+len("Bootstrapped "):]
				if j := strings.IndexByte(rest, '%'); j > 0 {
					if pct, err := strconv.Atoi(strings.TrimSpace(rest[:j])); err == nil && pct != w.lastPct {
						w.lastPct = pct
						w.onProgress(pct)
					}
				}
			}
		}
		// Send to the channel (non-blocking: if full, silently discard)
		select {
		case w.ch <- line:
		default:
		}
	}
	return len(p), nil
}

// macDylibRuntimeName is the name libevent must be extracted under
// alongside the tor binary on macOS: the embedded tor references it as
// "@executable_path/libevent-2.1.7.dylib" (load command fixed at build
// time by the Tor Project), so the on-disk file name must match
// exactly. An embedded Tor shipping a different libevent requires
// updating this constant accordingly.
const macDylibRuntimeName = "libevent-2.1.7.dylib"

// extractBinary writes the embedded tor binary into a dedicated
// temporary directory and makes it executable. On macOS it also
// extracts libevent.dylib into the same directory (the embedded tor
// isn't static on this platform, unlike linux/amd64) and applies an
// ad-hoc signature to both files: on Apple Silicon the kernel refuses
// to run a Mach-O with no signature at all. Returns the tor binary's
// path and a cleanup function to call when the tor process closes.
func extractBinary() (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "neutrino-tor-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	path = filepath.Join(dir, "tor")
	if err = os.WriteFile(path, torBinary, 0700); err != nil {
		cleanup()
		return "", nil, err
	}

	if runtime.GOOS == "darwin" && len(dylibBinary) > 0 {
		dylibPath := filepath.Join(dir, macDylibRuntimeName)
		if err = os.WriteFile(dylibPath, dylibBinary, 0644); err != nil {
			cleanup()
			return "", nil, err
		}
		if err = adhocSignDarwin(dylibPath); err != nil {
			cleanup()
			return "", nil, err
		}
	}

	if err = adhocSignDarwin(path); err != nil {
		cleanup()
		return "", nil, err
	}

	return path, cleanup, nil
}

// adhocSignDarwin applies an ad-hoc signature (codesign --sign -) to the
// given file. No-op on platforms other than macOS. Necessary because
// the tor/lyrebird binaries in the official Tor Project bundle aren't
// signed at all: on Apple Silicon the kernel refuses to map a
// completely unsigned Mach-O as executable, even ad-hoc. codesign is
// part of the OS (doesn't require Xcode).
func adhocSignDarwin(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("codesign", "--force", "--sign", "-", path).CombinedOutput()
	if err != nil {
		return errors.New(i18n.T("tornode.err_codesign", path, err, string(out)))
	}
	return nil
}

// WatchHSPublished blocks until the hidden service descriptor for
// onionAddr is uploaded to the Tor directory servers (HS_DESC UPLOADED
// event). Returns true on success, false if ctx is canceled before publication.
func (n *Node) WatchHSPublished(ctx context.Context, onionAddr string) bool {
	if n.t == nil || n.t.Control == nil {
		return false
	}
	addr := strings.TrimSuffix(onionAddr, ".onion")
	_, err := n.t.Control.EventWait(ctx,
		[]control.EventCode{control.EventCodeHSDesc},
		func(e control.Event) (bool, error) {
			ev, ok := e.(*control.HSDescEvent)
			return ok && ev.Action == "UPLOADED" && ev.Address == addr, nil
		},
	)
	return err == nil
}

// HasCircuits returns true if Tor has at least one circuit in BUILT
// state. Uses the control port, doesn't require SOCKS5 connections and
// responds in milliseconds.
func (n *Node) HasCircuits() bool {
	if n.t == nil || n.t.Control == nil {
		return false
	}
	kvs, err := n.t.Control.GetInfo("circuit-status")
	if err != nil {
		return false
	}
	for _, kv := range kvs {
		if strings.Contains(kv.Val, "BUILT") {
			return true
		}
	}
	return false
}

// DialContext connects to network/addr through Tor's SOCKS5 proxy.
// The SOCKS5 dialer is created once (on first use) and reused for all
// subsequent connections: avoids a round-trip to the control port for
// every connection and makes calls immune to the caller's HTTP context
// timeout during init.
func (n *Node) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	if n.dialer == nil {
		d, err := n.t.Dialer(context.Background(), nil)
		if err != nil {
			n.mu.Unlock()
			return nil, errors.New(i18n.T("tornode.err_dialer", err))
		}
		n.dialer = d
	}
	d := n.dialer
	n.mu.Unlock()
	return d.DialContext(ctx, network, addr)
}

// SocksAddr returns the local "host:port" of Tor's SOCKS5 proxy, queried
// live from the control port (same GETINFO net/listeners/socks lookup
// bine's own Dialer does internally, see cretz/bine@v0.2.0/tor/dialer.go)
// rather than cached, since the embedded tor always starts with
// "--SocksPort auto" and the port is only known after Tor has bound it.
func (n *Node) SocksAddr() (string, error) {
	n.mu.Lock()
	t := n.t
	n.mu.Unlock()
	if t == nil {
		return "", errors.New(i18n.T("tornode.err_socks_addr", errors.New("tor not started")))
	}
	info, err := t.Control.GetInfo("net/listeners/socks")
	if err != nil {
		return "", errors.New(i18n.T("tornode.err_socks_addr", err))
	}
	if len(info) != 1 || info[0].Key != "net/listeners/socks" || strings.HasPrefix(info[0].Val, "unix:") {
		return "", errors.New(i18n.T("tornode.err_socks_addr", errors.New("no tcp socks listener")))
	}
	return info[0].Val, nil
}

// DialerForToken returns a DialContext that uses a Tor circuit isolated
// for the token. Connections with the same token share the circuit;
// different tokens get separate circuits via IsolateSOCKSAuth (distinct
// SOCKS5 credentials). The dialer is created once per token and reused
// for subsequent connections. ctx covers only this construction
// (n.t.Dialer, which with bine doesn't do blocking network I/O, it
// only builds a local wrapper, SOCKS5 authentication happens on the
// first real dial), accepted anyway for consistency with the
// transport.Transport interface, of which this is the only real caller.
func (n *Node) DialerForToken(ctx context.Context, token string) (func(context.Context, string, string) (net.Conn, error), error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.isolatedDialers == nil {
		n.isolatedDialers = make(map[string]*tor.Dialer)
	}
	if d, ok := n.isolatedDialers[token]; ok {
		return d.DialContext, nil
	}
	d, err := n.t.Dialer(ctx, &tor.DialConf{
		ProxyAuth: &proxy.Auth{User: token, Password: token},
	})
	if err != nil {
		return nil, errors.New(i18n.T("tornode.err_isolated_dialer", token, err))
	}
	n.isolatedDialers[token] = d
	return d.DialContext, nil
}

// AddHiddenService creates a Tor v3 hidden service with the given
// Ed25519 key (standard Go format: seed || pubkey, 64 bytes).
// Returns a net.Listener, the full .onion address, and the local TCP
// address (e.g. "127.0.0.1:PORT") the listener accepts direct connections on.
// The hidden service exposes port 80 externally.
func (n *Node) AddHiddenService(ctx context.Context, privKey ed25519.PrivateKey) (net.Listener, string, string, error) {
	svc, err := n.t.Listen(ctx, &tor.ListenConf{
		RemotePorts: []int{80},
		Key:         tored25519.FromCryptoPrivateKey(privKey),
	})
	if err != nil {
		return nil, "", "", errors.New(i18n.T("tornode.err_hidden_service", err))
	}

	n.mu.Lock()
	n.svcs = append(n.svcs, svc)
	n.mu.Unlock()

	localAddr := svc.LocalListener.Addr().String()
	return svc, svc.ID + ".onion", localAddr, nil
}

// Close closes all hidden services and the Tor process.
// Also removes the embedded binary's temporary file, if present.
//
// bine leaves orphaned goroutines blocked on control.Conn.HandleNextEvent/Peek(3)
// with c.readLock held after t.Listen returns (HS published).
// Calling DelOnion or Signal("HALT") before the process exits leads to a deadlock.
// Solution: cancel the process first via ProcessCancelFunc, so the TCP
// closes, Peek(3) returns with an error, and c.readLock is released.
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Terminate the Tor process first to unblock any bine goroutines
	// stuck on Peek(3) with readLock held.
	if n.t != nil && n.t.ProcessCancelFunc != nil {
		n.t.ProcessCancelFunc()
	}
	// Brief wait for the TCP to close and the goroutines to release readLock.
	time.Sleep(150 * time.Millisecond)
	for _, svc := range n.svcs {
		svc.Close() // can fail (connection already closed), error ignored
	}
	n.svcs = nil
	err := n.t.Close()
	if n.cleanup != nil {
		n.cleanup()
	}
	if n.ptc != nil {
		n.ptc.Close()
	}
	return err
}
