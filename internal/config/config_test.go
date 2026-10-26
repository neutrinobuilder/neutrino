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

package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"neutrino/internal/config"
)

func TestDefaultValues(t *testing.T) {
	cfg := config.Default()
	if cfg.Lang != "en" {
		t.Errorf("Lang: want 'en', got %q", cfg.Lang)
	}
	if cfg.Net != "tor" {
		t.Errorf("Net: want 'tor', got %q", cfg.Net)
	}
	if cfg.PingDuration() != time.Minute {
		t.Errorf("PingDuration: want 1m, got %v", cfg.PingDuration())
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := config.Default()
	cfg.Lang = "en"
	cfg.PingInterval = "45s"
	cfg.BridgesEnabled = true
	cfg.InterfaceLockTimeout = "45s"

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("want permissions 0600, got %o", info.Mode().Perm())
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Lang != "en" {
		t.Errorf("Lang after the roundtrip: want 'en', got %q", got.Lang)
	}
	if got.PingInterval != "45s" {
		t.Errorf("PingInterval after the roundtrip: want '45s', got %q", got.PingInterval)
	}
	if !got.BridgesEnabled {
		t.Error("BridgesEnabled after the roundtrip: want true")
	}
	if got.InterfaceLockTimeout != "45s" {
		t.Errorf("InterfaceLockTimeout after the roundtrip: want '45s', got %q", got.InterfaceLockTimeout)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	got, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Error("Load on a missing file: want an error")
	}
	if got != config.Default() {
		t.Error("Load on a missing file: want the default values anyway")
	}
}

func TestLoadMalformedJSONReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{ not valid json"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := config.Load(path)
	if err == nil {
		t.Error("Load on malformed JSON: want an error")
	}
	if got != config.Default() {
		t.Error("Load on malformed JSON: want the default values anyway")
	}
}

func TestLoadIgnoresCommentLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := "{\n  # this is a comment\n  \"lang\": \"en\"\n}\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Lang != "en" {
		t.Errorf("Lang: want 'en' (# lines ignored), got %q", got.Lang)
	}
}

func TestDurationMethodsFallBackOnInvalidValue(t *testing.T) {
	cfg := config.Default()

	cfg.PingInterval = "not-a-duration"
	if got := cfg.PingDuration(); got != time.Minute {
		t.Errorf("PingDuration with an invalid value: want the default 1m, got %v", got)
	}

	cfg.PingInterval = "-5s"
	if got := cfg.PingDuration(); got != time.Minute {
		t.Errorf("PingDuration with a negative duration: want the default 1m, got %v", got)
	}

	cfg.PingInterval = "45s"
	if got := cfg.PingDuration(); got != 45*time.Second {
		t.Errorf("PingDuration with a valid value: want 45s, got %v", got)
	}
}

// TestFallbackDurationsMatchDefault checks that each *Duration() method's
// internal fallback matches the value config.Default() actually writes to
// disk for a fresh install, never observable with a well-formed
// config.json (the fallback only triggers on an empty/corrupt value), but
// otherwise a value diverging from what the config file and public manuals
// document.
func TestFallbackDurationsMatchDefault(t *testing.T) {
	def := config.Default()
	corrupt := config.Config{
		ActiveInterval: "not-a-duration",
		WarmupInterval: "not-a-duration",
	}
	if got, want := corrupt.ActiveDuration(), def.ActiveDuration(); got != want {
		t.Errorf("ActiveDuration fallback: want %v (default), got %v", want, got)
	}
	if got, want := corrupt.WarmupIntervalDuration(), def.WarmupIntervalDuration(); got != want {
		t.Errorf("WarmupIntervalDuration fallback: want %v (default), got %v", want, got)
	}
}

func TestClampPositiveIntMethods(t *testing.T) {
	cfg := config.Default()

	cfg.ProbeRetryCount = 0
	if got := cfg.ProbeRetryCountOrDefault(); got != 3 {
		t.Errorf("ProbeRetryCountOrDefault with 0: want default 3, got %d", got)
	}
	cfg.ProbeRetryCount = -1
	if got := cfg.ProbeRetryCountOrDefault(); got != 3 {
		t.Errorf("ProbeRetryCountOrDefault with a negative value: want default 3, got %d", got)
	}
	cfg.ProbeRetryCount = 7
	if got := cfg.ProbeRetryCountOrDefault(); got != 7 {
		t.Errorf("ProbeRetryCountOrDefault with a valid value: want 7, got %d", got)
	}
}

func TestReliableDeliveryDefaults(t *testing.T) {
	cfg := config.Default()

	if got := cfg.SenderKeyMessageBudgetOrDefault(); got != 25 {
		t.Errorf("SenderKeyMessageBudgetOrDefault: want 25, got %d", got)
	}
	if got := cfg.PendingSlotLimitOrDefault(); got != 5 {
		t.Errorf("PendingSlotLimitOrDefault: want 5, got %d", got)
	}
	if got, want := cfg.PendingEscalationAgeDuration(), 90*time.Second; got != want {
		t.Errorf("PendingEscalationAgeDuration: want %v, got %v", want, got)
	}
	if got, want := cfg.MessageRetryDelayDuration(), 20*time.Second; got != want {
		t.Errorf("MessageRetryDelayDuration: want %v, got %v", want, got)
	}

	cfg.SenderKeyMessageBudget = 0
	if got := cfg.SenderKeyMessageBudgetOrDefault(); got != 25 {
		t.Errorf("SenderKeyMessageBudgetOrDefault with 0: want default 25, got %d", got)
	}
	cfg.PendingSlotLimit = -1
	if got := cfg.PendingSlotLimitOrDefault(); got != 5 {
		t.Errorf("PendingSlotLimitOrDefault with a negative value: want default 5, got %d", got)
	}
	cfg.PendingEscalationAge = "not-a-duration"
	if got, want := cfg.PendingEscalationAgeDuration(), 90*time.Second; got != want {
		t.Errorf("PendingEscalationAgeDuration with a corrupt value: want fallback %v, got %v", want, got)
	}
	cfg.MessageRetryDelay = "not-a-duration"
	if got, want := cfg.MessageRetryDelayDuration(), 20*time.Second; got != want {
		t.Errorf("MessageRetryDelayDuration with a corrupt value: want fallback %v, got %v", want, got)
	}
}

func TestFileSlowDelayDuration(t *testing.T) {
	cfg := config.Default()

	cfg.FileSlowDelayMs = 0
	if got := cfg.FileSlowDelayDuration(); got != 250*time.Millisecond {
		t.Errorf("FileSlowDelayDuration with 0: want default 250ms, got %v", got)
	}
	cfg.FileSlowDelayMs = 500
	if got := cfg.FileSlowDelayDuration(); got != 500*time.Millisecond {
		t.Errorf("FileSlowDelayDuration with a valid value: want 500ms, got %v", got)
	}
}
