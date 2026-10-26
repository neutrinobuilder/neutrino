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

// Package dohresolver resolves domain names via DNS-over-HTTPS (RFC 8484),
// with fallback across several providers. On Android, DNS is handled by
// netd/Bionic rather than /etc/resolv.conf; the statically linked, musl-built
// i2pd binary calls the system resolver for its initial reseed and that
// lookup fails there. Bypassing the system resolver entirely with a Go DoH
// client avoids the failure without any file to regenerate periodically.
// Applied on every platform, not just Android: it also keeps I2P reseed
// lookups off the system DNS resolver (typically the ISP's, unencrypted).
package dohresolver

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"

	"golang.org/x/net/dns/dnsmessage"
)

// caBundlePEM is the embedded CA bundle (Mozilla root set, via the Debian
// ca-certificates package), used in place of the system pool to verify the
// TLS certificate of DoH providers. The binary is built for GOOS=linux, so
// x509.SystemCertPool() looks for the CA bundle at the hard-coded paths in
// root_linux.go (/etc/ssl/certs/..., /etc/pki/...), none of which exist on
// Termux, which keeps its own under $PREFIX/etc/tls/; an empty system pool
// would fail every TLS verification, not just DNS resolution.
//
//go:embed cacert.pem
var caBundlePEM []byte

var (
	caPoolOnce sync.Once
	caPool     *x509.CertPool
)

func rootCAs() *x509.CertPool {
	caPoolOnce.Do(func() {
		caPool = x509.NewCertPool()
		caPool.AppendCertsFromPEM(caBundlePEM)
	})
	return caPool
}

// provider is a DoH endpoint queried through a fixed (anycast) IP, bypassing
// DNS resolution of its own hostname entirely, the standard Go client would
// otherwise resolve "cloudflare-dns.com" and similar through the same system
// resolver this package exists to bypass. The hostname is still used for SNI
// and certificate verification; only the TCP connection address is fixed.
type provider struct {
	url  string   // full DoH endpoint, for the HTTP request body
	host string   // hostname for SNI/certificate verification (parsed from url)
	ips  []string // known, stable anycast IP:port pairs, tried in order
}

// providers is the list of DoH endpoints queried in order, stopping at the
// first success.
var providers = []provider{
	{
		url:  "https://cloudflare-dns.com/dns-query",
		host: "cloudflare-dns.com",
		ips:  []string{"1.1.1.1:443", "1.0.0.1:443"},
	},
	{
		url:  "https://dns.quad9.net/dns-query",
		host: "dns.quad9.net",
		ips:  []string{"9.9.9.9:443", "149.112.112.112:443"},
	},
	{
		url:  "https://dns.google/dns-query",
		host: "dns.google",
		ips:  []string{"8.8.8.8:443", "8.8.4.4:443"},
	},
}

// newProviderClient builds an HTTP client dedicated to a provider, whose TCP
// connection is always established against one of its known fixed IPs
// (never through DNS resolution of the hostname), tried in order.
func newProviderClient(p provider) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var lastErr error
				for _, ip := range p.ips {
					conn, err := dialer.DialContext(ctx, network, ip)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			},
			TLSClientConfig: &tls.Config{
				ServerName: p.host,
				RootCAs:    rootCAs(),
			},
		},
	}
}

// Lookup resolves host to a list of IPv4 addresses (A records), trying each
// DoH provider in order until one responds with at least one address. If
// host is already a literal IP address, it is returned directly with no DNS
// query.
func Lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	var lastErr error
	for _, p := range providers {
		ips, err := queryProvider(ctx, p, host)
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("dohresolver: no address found for " + host)
	}
	return nil, lastErr
}

// queryProvider queries a single DoH endpoint for the A records of host.
func queryProvider(ctx context.Context, p provider, host string) ([]net.IP, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano()),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := newProviderClient(p).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("dohresolver: " + p.url + ": HTTP " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var respMsg dnsmessage.Message
	if err := respMsg.Unpack(body); err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, a := range respMsg.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, net.IP(r.A[:]))
		}
	}
	return ips, nil
}
