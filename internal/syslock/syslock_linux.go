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

//go:build linux && !android

// Package syslock watches the host OS for an explicit session-lock signal,
// so Neutrino's own interface lock can react immediately instead of only
// through its internal inactivity timer.
package syslock

import (
	"context"
	"os"

	"github.com/godbus/dbus/v5"
)

// Watch subscribes to systemd-logind's Session "Lock" signal for the
// caller's own session (system bus, org.freedesktop.login1) and returns
// a channel that receives one value each time the signal fires. Returns
// nil if the system bus or logind session cannot be reached (no logind,
// no D-Bus, session not tracked by logind) — same "feature unavailable"
// contract as ScanCamera on this platform. Never reacts to "Unlock": this
// project's interface lock is only ever released through its own
// configured secret, never by an OS signal.
func Watch(ctx context.Context) <-chan struct{} {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil
	}
	var sessionPath dbus.ObjectPath
	manager := conn.Object("org.freedesktop.login1", dbus.ObjectPath("/org/freedesktop/login1"))
	if err := manager.CallWithContext(ctx, "org.freedesktop.login1.Manager.GetSessionByPID", 0, uint32(os.Getpid())).Store(&sessionPath); err != nil {
		conn.Close()
		return nil
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(sessionPath),
		dbus.WithMatchInterface("org.freedesktop.login1.Session"),
		dbus.WithMatchMember("Lock"),
	); err != nil {
		conn.Close()
		return nil
	}

	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	out := make(chan struct{}, 1)
	go func() {
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-signals:
				if !ok {
					return
				}
				if sig.Name != "org.freedesktop.login1.Session.Lock" {
					continue
				}
				select {
				case out <- struct{}{}:
				default: // already one pending, the lock is idempotent anyway
				}
			}
		}
	}()
	return out
}
