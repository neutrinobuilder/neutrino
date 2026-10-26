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

// Package i2pnode manages the i2pd process embedded in the binary.
// On linux/amd64 and linux/arm64 (e.g. Termux/Android) the i2pd binary
// is embedded directly (go:embed, static musl/Alpine build, see
// download_build_i2pd.sh); on other platforms the system `i2pd` daemon is
// used as a fallback, the same scheme as internal/tornode for Tor.
//
// Unlike tornode, this package deals only with the process's lifecycle
// (startup, binary extraction, logging, shutdown): the SAM protocol
// (sessions, destinations, dial/accept) lives entirely in
// internal/transport, this package's only consumer.
//
// To update the embedded binary or add support for a new platform:
//
//	bash internal/i2pnode/download_build_i2pd.sh
//
//go:generate bash download_build_i2pd.sh
package i2pnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"neutrino/internal/androidnative"
	"neutrino/internal/dohresolver"
	"neutrino/internal/i18n"
	"neutrino/internal/safeexec"
)

// Node manages the i2pd process and its SAM bridge.
type Node struct {
	cmd     *exec.Cmd
	cleanup func() // removes the extracted binary (if embedded) and the temporary datadir
	samAddr string // "127.0.0.1:PORT", ready to use: Start returns only after the accept
	logCh   chan string
}

// SAMAddr returns the SAM bridge's "host:port" address.
func (n *Node) SAMAddr() string { return n.samAddr }

// LogCh returns the i2pd process's log channel, one line per element.
// Buffered (2000 elements, a ring buffer: when full it discards the
// oldest line, not the newly arriving one, so a later dump always shows
// the most recent events, the ones useful for understanding a timeout).
func (n *Node) LogCh() <-chan string { return n.logCh }

// Close stops the i2pd process and releases its resources (extracted
// binary, temporary datadir). Doesn't call cmd.Process.Wait(): the reap
// happens in the goroutine started by Start (cmd.Wait() can only be
// called once on the same *exec.Cmd).
func (n *Node) Close() error {
	if n.cmd != nil && n.cmd.Process != nil {
		_ = n.cmd.Process.Kill()
	}
	if n.cleanup != nil {
		n.cleanup()
	}
	return nil
}

// StartI2p starts the i2pd process with the SAM bridge enabled on a free
// local port and waits for it to accept connections (up to 3 minutes).
// If an i2pd binary is embedded in the program, it's extracted to a
// temporary directory and used; otherwise the `i2pd` daemon found on the
// system PATH is used.
func StartI2p(ctx context.Context) (*Node, error) {
	exePath, binCleanup, err := resolveBinary()
	if err != nil {
		return nil, err
	}

	samPort, err := freeTCPPort()
	if err != nil {
		if binCleanup != nil {
			binCleanup()
		}
		return nil, err
	}
	samAddr := fmt.Sprintf("127.0.0.1:%d", samPort)

	dataDir, err := os.MkdirTemp("", "neutrino-i2pd-*")
	if err != nil {
		if binCleanup != nil {
			binCleanup()
		}
		return nil, err
	}
	// Local DoH proxy for reseed: the i2pd binary is static (musl) and
	// its system resolver reads /etc/resolv.conf, unusable on
	// Android/Termux (DNS there goes through netd/Bionic, not that
	// file), every reseed lookup fails with "Host not found". The proxy
	// resolves hosts via DNS-over-HTTPS in Go, bypassing the system
	// resolver entirely, applied on every platform, not just Android:
	// it also keeps the system DNS resolver (often
	// the ISP's, in the clear) from seeing I2P reseed requests. See
	// internal/dohresolver.
	dohProxy, err := dohresolver.StartProxy()
	if err != nil {
		if binCleanup != nil {
			binCleanup()
		}
		return nil, err
	}

	cleanup := func() {
		dohProxy.Close()
		os.RemoveAll(dataDir)
		if binCleanup != nil {
			binCleanup()
		}
	}

	logCh := make(chan string, 2000)
	lw := &logWriter{ch: logCh}

	cmd := exec.CommandContext(ctx, exePath,
		"--datadir="+dataDir,
		"--log=stdout",
		"--loglevel=info",
		"--sam.enabled=true",
		"--sam.address=127.0.0.1",
		fmt.Sprintf("--sam.port=%d", samPort),
		"--http.enabled=false",
		"--httpproxy.enabled=false",
		"--socksproxy.enabled=false",
		"--upnp.enabled=false",
		"--reseed.proxy=http://"+dohProxy.Addr(),
	)
	cmd.Stdout = lw
	cmd.Stderr = lw

	if err := cmd.Start(); err != nil {
		cleanup()
		hint := ""
		if len(i2pdBinary) == 0 {
			hint = i18n.T("i2pnode.hint_install_i2pd")
		}
		return nil, errors.New(i18n.T("i2pnode.err_start", err, hint))
	}

	// cmd.Wait() must be called exactly once in the process's lifetime
	// (otherwise panic "exec: Wait was already called"), this goroutine
	// is the only place that does it, both for reaping and for detecting
	// an early exit (e.g. a crash) while waitSAMReady is still waiting.
	exitedCh := make(chan error, 1)
	go func() { exitedCh <- cmd.Wait() }()

	// Shorter than the generic network-startup watchdog in cmd/main.go
	// (3 minutes), so this one expires first: the generic one has no
	// visibility into the i2pd log and would report only "bootstrap
	// incomplete", never the log below.
	if err := waitSAMReady(ctx, samAddr, 2*time.Minute+30*time.Second, exitedCh); err != nil {
		_ = cmd.Process.Kill()
		cleanup()
		if dump := drainLog(logCh); dump != "" {
			err = errors.New(err.Error() + dump)
		}
		return nil, err
	}

	return &Node{cmd: cmd, cleanup: cleanup, samAddr: samAddr, logCh: logCh}, nil
}

// resolveBinary returns the path of the i2pd executable to launch: the
// embedded one (extracted to a temporary directory) if present for this
// platform, otherwise the one found on the system PATH.
func resolveBinary() (path string, cleanup func(), err error) {
	if runtime.GOOS == "android" {
		// The real binary (libi2pd.so, PurpleI2P/i2pd-android, a
		// standalone ELF, not disguised) isn't go:embed, it arrives in
		// the APK via jniLibs/<abi>/ and is already executable
		// (755) because it's extracted by the PackageManager into
		// nativeLibraryDir: no writing, no chmod, no cleanup.
		dir, _, err := androidnative.Resolve()
		if err != nil {
			return "", nil, errors.New(i18n.T("i2pnode.err_android_native_lib_dir", err))
		}
		path := filepath.Join(dir, "libi2pd.so")
		if _, err := os.Stat(path); err != nil {
			return "", nil, errors.New(i18n.T("i2pnode.err_android_i2pd_missing", err))
		}
		return path, nil, nil
	}
	if len(i2pdBinary) > 0 {
		path, cleanup, err = extractBinary()
		if err != nil {
			return "", nil, errors.New(i18n.T("i2pnode.err_extract_embedded", err))
		}
		return path, cleanup, nil
	}
	found, err := safeexec.LookPath("i2pd")
	if err != nil {
		return "", nil, errors.New(i18n.T("i2pnode.err_start", err, i18n.T("i2pnode.hint_install_i2pd")))
	}
	return found, nil, nil
}

// extractBinary writes the embedded i2pd binary to a dedicated temporary
// directory and makes it executable.
func extractBinary() (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "neutrino-i2pd-bin-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	path = filepath.Join(dir, "i2pd")
	if err = os.WriteFile(path, i2pdBinary, 0700); err != nil {
		cleanup()
		return "", nil, err
	}
	if err = adhocSignDarwin(path); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// adhocSignDarwin applies an ad-hoc signature (codesign --sign -) to the
// given file. No-op on platforms other than macOS. Needed because the
// official i2pd binary for macOS isn't signed at all: on Apple Silicon
// the kernel refuses to map an unsigned Mach-O as executable, even
// ad-hoc, same reason, same solution as internal/tornode.adhocSignDarwin
// for Tor. codesign is part of the operating system (doesn't require
// Xcode).
func adhocSignDarwin(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("codesign", "--force", "--sign", "-", path).CombinedOutput()
	if err != nil {
		return errors.New(i18n.T("i2pnode.err_codesign", path, err, string(out)))
	}
	return nil
}

func freeTCPPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitSAMReady(ctx context.Context, samAddr string, timeout time.Duration, exited <-chan error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-exited:
			return errors.New(i18n.T("i2pnode.err_process_exited", err))
		default:
		}
		conn, err := net.DialTimeout("tcp", samAddr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New(i18n.T("i2pnode.err_sam_timeout", samAddr, lastErr))
}

// drainLog non-blockingly collects every line already arrived on ch (the
// i2pd log buffered during startup) into a single string, so it can be
// included in the error when the process never manages to open the SAM
// bridge, otherwise those lines stay buffered in the channel and are
// lost when Start returns an error (the Node, and therefore LogCh(), is
// never returned to the caller on that path).
func drainLog(ch <-chan string) string {
	var lines []string
	for {
		select {
		case line := <-ch:
			lines = append(lines, line)
		default:
			if len(lines) == 0 {
				return ""
			}
			return i18n.T("i2pnode.log_dump", strings.Join(lines, "\n"))
		}
	}
}

// ansiEscapeRe recognizes ANSI escape sequences (terminal colors, e.g.
// "\x1b[1;36m"/"\x1b[0m") that i2pd writes unconditionally to its own
// stdout even with "--log=stdout", unlike Tor (internal/tornode), which
// never colors its own log. Without this cleanup the sequences would
// arrive intact at the log channel and end up displayed as literal text
// (e.g. "␛[1;36minfo␛[0m") in whatever screen shows them
// (screens/network_log.go on Android, the desktop TUI's "Network" tab,
// both consume the same internal/i2pnode.Node.LogCh(), so fixing it here
// in one place covers both platforms).
var ansiEscapeRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// logWriter forwards the i2pd process's stdout/stderr lines to the log
// channel, the same scheme as torWriter in internal/tornode, without
// progress parsing (i2pd exposes no granular signal like "Bootstrapped
// X%").
type logWriter struct {
	ch  chan string // bidirectional: the ring buffer must also be able to drain the oldest line
	buf []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := ansiEscapeRe.ReplaceAllString(strings.TrimRight(string(w.buf[:i]), "\r"), "")
		w.buf = w.buf[i+1:]
		if line == "" {
			continue
		}
		select {
		case w.ch <- line:
		default:
			// Channel full: discard the oldest line to make room for the
			// new one, not the other way around, otherwise a later dump
			// would show only the oldest events (e.g. the first seconds
			// of startup), never the ones close to a timeout.
			select {
			case <-w.ch:
			default:
			}
			select {
			case w.ch <- line:
			default:
			}
		}
	}
	return len(p), nil
}
