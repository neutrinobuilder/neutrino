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
	"os"
	"strings"
	"testing"
)

func TestPrepareBridgeArgsEmpty(t *testing.T) {
	pc, args, err := prepareBridgeArgs(&BridgeConfig{})
	if err != nil {
		t.Fatalf("prepareBridgeArgs: %v", err)
	}
	if pc != nil {
		t.Fatal("pc must not be set without bridges")
	}
	want := []string{"--UseBridges", "1"}
	if len(args) != len(want) || args[0] != want[0] || args[1] != want[1] {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestPrepareBridgeArgsPlainIPNoPluggableTransport(t *testing.T) {
	bc := &BridgeConfig{Lines: []string{"Bridge 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567"}}
	pc, args, err := prepareBridgeArgs(bc)
	if err != nil {
		t.Fatalf("prepareBridgeArgs: %v", err)
	}
	if pc != nil {
		t.Fatal("pc must not be set for a plain IP bridge (no pluggable transport needed)")
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--Bridge 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567") {
		t.Fatalf("args = %v, want the bridge without the \"Bridge \" prefix", args)
	}
	if strings.Contains(joined, "ClientTransportPlugin") {
		t.Fatalf("args = %v, ClientTransportPlugin not expected for a plain IP bridge", args)
	}
}

func TestPrepareBridgeArgsSkipsCommentsAndBlank(t *testing.T) {
	bc := &BridgeConfig{Lines: []string{
		"",
		"# a comment",
		"   ",
		"Bridge 5.6.7.8:9001 FEDCBA9876543210FEDCBA9876543210FEDCBA98",
	}}
	_, args, err := prepareBridgeArgs(bc)
	if err != nil {
		t.Fatalf("prepareBridgeArgs: %v", err)
	}
	n := 0
	for _, a := range args {
		if a == "--Bridge" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 --Bridge line (empty lines/comments discarded), found %d in %v", n, args)
	}
}

func TestPrepareBridgeArgsObfs4NeedsTransportPlugin(t *testing.T) {
	bc := &BridgeConfig{Lines: []string{
		"obfs4 9.9.9.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0",
	}}
	pc, args, err := prepareBridgeArgs(bc)
	if err != nil {
		t.Fatalf("prepareBridgeArgs: %v", err)
	}
	if pc == nil {
		t.Fatal("nil pc: want the obfs4 transport started in-process")
	}
	defer pc.Close()

	var pluginArg string
	for _, a := range args {
		if strings.HasPrefix(a, "obfs4 socks5 ") {
			pluginArg = a
			break
		}
	}
	if pluginArg == "" {
		t.Fatalf("args = %v, want an \"obfs4 socks5 <addr>\" value after --ClientTransportPlugin", args)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--ClientTransportPlugin "+pluginArg) {
		t.Fatalf("args = %v, want --ClientTransportPlugin right before %q", args, pluginArg)
	}
	addr := strings.TrimPrefix(pluginArg, "obfs4 socks5 ")
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("pluggable transport address = %q, want a local 127.0.0.1:<port> listener", addr)
	}
}

func TestPrepareBridgeArgsWebtunnelUsesOwnTransportName(t *testing.T) {
	bc := &BridgeConfig{Lines: []string{
		"webtunnel 8.8.8.8:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/x ver=1",
	}}
	pc, args, err := prepareBridgeArgs(bc)
	if err != nil {
		t.Fatalf("prepareBridgeArgs: %v", err)
	}
	if pc == nil {
		t.Fatal("nil pc: want the webtunnel transport started in-process")
	}
	defer pc.Close()

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--ClientTransportPlugin webtunnel socks5 127.0.0.1:") {
		// The plugin name must match the actual transport requested by
		// the bridge line, never a hardcoded value.
		t.Fatalf("args = %v, want ClientTransportPlugin for webtunnel (not obfs4)", args)
	}
	if strings.Contains(joined, "obfs4") {
		t.Fatalf("args = %v, no reference to obfs4 expected for a webtunnel-only bridge", args)
	}
}

func TestExtractBinaryWritesExecutable(t *testing.T) {
	if len(torBinary) == 0 {
		t.Skip("no embedded tor binary for this target")
	}
	path, cleanup, err := extractBinary()
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	defer cleanup()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if fi.Mode()&0100 == 0 {
		t.Fatalf("%q is not executable (mode %v)", path, fi.Mode())
	}
	if fi.Size() != int64(len(torBinary)) {
		t.Fatalf("file size = %d, want %d (torBinary)", fi.Size(), len(torBinary))
	}

	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("cleanup: the file should have been removed")
	}
}
