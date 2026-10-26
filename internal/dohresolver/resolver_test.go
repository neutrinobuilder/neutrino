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

package dohresolver

import (
	"context"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

// TestLookupLiteralIPv4 checks the shortcut that skips a DNS-over-HTTPS
// query entirely when host is already an IP address, the only path through
// Lookup testable without real network access, since actual DoH queries hit
// Cloudflare/Quad9/Google.
func TestLookupLiteralIPv4(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ips, err := Lookup(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("Lookup = %v, want [1.2.3.4]", ips)
	}
}

func TestLookupLiteralIPv6(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ips, err := Lookup(ctx, "::1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("Lookup = %v, want [::1]", ips)
	}
}

func TestRootCAsLoadsEmbeddedBundle(t *testing.T) {
	if rootCAs() == nil {
		t.Fatal("rootCAs() = nil")
	}
	// Counts the PEM blocks of the embedded bundle directly (rather than
	// going through x509.CertPool, whose only inspection API, Subjects(),
	// is deprecated), if cacert.pem were empty or corrupt,
	// AppendCertsFromPEM would add nothing without failing loudly.
	n := 0
	rest := caBundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
	if n == 0 {
		t.Fatal("cacert.pem: no CERTIFICATE block found, the bundle looks empty/corrupt")
	}
}

func TestRootCAsIsSingleton(t *testing.T) {
	first := rootCAs()
	second := rootCAs()
	if first != second {
		t.Fatal("rootCAs(): want the same *x509.CertPool on every call (sync.Once)")
	}
}
