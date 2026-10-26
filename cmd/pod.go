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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"neutrino/internal/keystore"
	"neutrino/internal/shared"
	"neutrino/internal/transport"
)

// podTimeout bounds how long the pod retries delivery across the whole
// batch of targets — same ~20s budget as remoteNukeExecuteTimeout
// elsewhere in this codebase. Every trigger that reaches the pod goes
// through an already-unlocked TUI session, so a single uniform budget is
// enough.
const podTimeout = 20 * time.Second

// podRetryDelay is how long the pod waits between retries of the same
// target within podTimeout — short on purpose: the whole budget is only
// ~20s, a long backoff would leave no room for a second attempt.
const podRetryDelay = 2 * time.Second

// podColdBootTimeout bounds how long the pod waits for its OWN Tor/I2P
// bootstrap when no live parent proxy was inherited (PodSnapshot.ProxyAddr
// empty — e.g. duress at the login screen, where unlockKeystoreSession
// runs before transport.Start ever does in the parent, so no network
// exists yet to inherit from). Generous on purpose, same order of
// magnitude as tornode.DefaultBridgeBootstrapTimeout: a slow Tor
// bootstrap is normal, giving up early here would silently orphan every
// contact's revoke with no retry ever coming.
const podColdBootTimeout = 90 * time.Second

// runPod is the pod's own entry point — reached only via self-exec with
// the hidden "__pod" subcommand (see spawnPod), never invoked directly
// by a user. Reads its snapshot EXCLUSIVELY from stdin (never argv/env),
// then delivers the revoke it carries. Never touches any keystore file,
// never holds any private key.
//
// Stays silent on stdout/stderr by design, same anti-forensic principle
// as runNukeOverwriteInPlace: a pod that prints anything would be
// visible evidence on whatever's left of the screen/terminal at the
// moment it runs.
func runPod() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0)
	}
	var snapshot keystore.PodSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		os.Exit(0)
	}
	deliverPodRevokes(snapshot)
	os.Exit(0)
}

// podDialer builds a dial function routed according to netKind. If
// proxyAddr is non-empty, it's the inherited parent proxy/bridge:
// Tor's SOCKS5 for KindTor, i2pd's SAM bridge for KindI2P
// (transport.DialerSAM — SAM is NOT a SOCKS5 proxy, see
// internal/transport/i2p.go). If proxyAddr is empty, the pod cold-boots
// its OWN Tor/I2P node instead (transport.Start, bounded by ctx — the
// caller must size ctx's deadline to include podColdBootTimeout in this
// case) — no parent to inherit from (e.g. duress at the login screen).
// The cold-booted node is deliberately never closed: the pod process
// exits right after delivering (os.Exit(0) in runPod), orphaning it
// exactly like the parent's own already-orphaned Tor/I2P (no Setpgid,
// by design).
// Returns nil only if even that cold boot fails — in that case the
// caller must skip delivery entirely rather than fall back to a direct,
// non-anonymized connection.
func podDialer(ctx context.Context, proxyAddr string, netKind transport.Kind) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if proxyAddr == "" {
		node, err := transport.Start(ctx, netKind, transport.StartConfig{})
		if err != nil {
			return nil
		}
		return node.DialContext
	}
	if netKind == transport.KindI2P {
		dial, err := transport.DialerSAM(ctx, proxyAddr)
		if err != nil {
			return nil
		}
		return dial
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
}

// deliverPodRevokes sends the pre-generated rel_revoke toward every
// target in snapshot.Targets, in parallel, fire-and-forget — never
// waits for any acknowledgement of any kind (a real ack is the PARENT's
// job for siblings, reusing device_sync; the pod never deals with
// siblings at all).
func deliverPodRevokes(snapshot keystore.PodSnapshot) {
	if len(snapshot.Targets) == 0 {
		return
	}
	// A single shared ctx covers BOTH phases (cold boot, if any, then
	// delivery) — podDialer's cold-booted node must stay alive for the
	// whole call: canceling ctx early would kill its Tor/i2pd subprocess
	// (exec.CommandContext-tied, see internal/tornode/i2pnode) before
	// delivery even starts.
	budget := podTimeout
	if snapshot.ProxyAddr == "" {
		budget += podColdBootTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	dial := podDialer(ctx, snapshot.ProxyAddr, snapshot.NetKind)
	if dial == nil {
		return
	}

	httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}}

	var wg sync.WaitGroup
	for _, target := range snapshot.Targets {
		wg.Add(1)
		go func(target keystore.PodRevokeTarget) {
			defer wg.Done()
			deliverOnePodRevoke(ctx, httpCli, target)
		}(target)
	}
	wg.Wait()
}

// deliverOnePodRevoke builds and posts a single "rel_revoke" knock —
// same payload shape as sendRelRevoke (internal/client/tui/tui.go),
// minus MLKEMPub/FromAddr (no reply is ever expected or useful: the
// identity sending this is already being overwritten). Retries with
// podRetryDelay until ctx is done.
func deliverOnePodRevoke(ctx context.Context, httpCli *http.Client, target keystore.PodRevokeTarget) {
	if target.Address == "" || len(target.ContactIdentityPub) != ed25519.PublicKeySize || len(target.DHTag) == 0 {
		return
	}

	var recipientMLKEMPub *mlkem.EncapsulationKey768
	if len(target.ContactMLKEMPub) > 0 {
		if ek, err := mlkem.NewEncapsulationKey768(target.ContactMLKEMPub); err == nil {
			recipientMLKEMPub = ek
		}
	}

	kp := shared.KnockPayload{
		Type:            "rel_revoke",
		FromUsername:    target.FromUsername,
		FromIdentityPub: target.FromIdentityPub,
		RelRevoke: &shared.RelRevokePayload{
			DevicePub:        target.DevicePub,
			IdentitySig:      target.IdentitySig,
			IdentitySigMLDSA: target.IdentitySigMLDSA,
			ContentSig:       target.ContentSig,
			ContentSigMLDSA:  target.ContentSigMLDSA,
		},
	}
	payload, err := shared.EncryptKnockWithTag(ed25519.PublicKey(target.ContactIdentityPub), recipientMLKEMPub, kp, target.DHTag)
	if err != nil {
		return
	}

	url := "http://" + target.Address + "/knock"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "text/plain")
			if resp, err := httpCli.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(podRetryDelay):
		}
	}
}
