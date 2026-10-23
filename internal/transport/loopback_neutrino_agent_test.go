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
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"neutrino/internal/shared"
)

func TestLoopbackPublishDialClose(t *testing.T) {
	dir := t.TempDir()
	SetLoopbackDir(dir)
	defer SetLoopbackDir("")

	kind, err := ParseKind("loopback")
	if err != nil || kind != KindLoopback {
		t.Fatalf("ParseKind(loopback) = %q, %v", kind, err)
	}
	ctx := context.Background()
	node, err := Start(ctx, KindLoopback, StartConfig{})
	if err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ln, addr, _, err := node.AddHiddenService(ctx, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if want := shared.OnionAddressFromPub(priv.Public().(ed25519.PublicKey)); addr != want {
		t.Fatalf("addr = %q, want %q", addr, want)
	}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("ok"))
		c.Close()
	}()
	conn, err := node.DialContext(ctx, "tcp", addr+":80")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(conn)
	conn.Close()
	if string(got) != "ok" {
		t.Fatalf("read %q, want %q", got, "ok")
	}

	if _, err := node.DialContext(ctx, "tcp", "../escape:80"); err == nil {
		t.Fatal("dial of a path outside the shared directory must fail")
	}

	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, addr)); !os.IsNotExist(err) {
		t.Fatalf("published address still present after Close: %v", err)
	}
	if _, err := node.DialContext(ctx, "tcp", addr+":80"); err == nil {
		t.Fatal("dial after Close must fail")
	}
}
