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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"neutrino/internal/client/tui"
	"neutrino/internal/config"
	"neutrino/internal/i18n"
	"neutrino/internal/indoor"
	"neutrino/internal/keystore"
	"neutrino/internal/transport"
)

// agentCreds replaces the wizard's and the login's terminal input in
// agent mode. Read from a file only readable by its owner, never from
// the command line (visible to every local user through ps).
type agentCreds struct {
	Username               string `json:"username"`
	PasswordFile           string `json:"password_file"`
	PasswordIdentity       string `json:"password_identity"`
	DuressUsername         string `json:"duress_username"`
	DuressPasswordIdentity string `json:"duress_password_identity"`
	DeviceLabel            string `json:"device_label"`
	// RestoreFrom, if set on first start, names a directory written by
	// --export-backup: the keystore is restored from its 24 words and
	// backup file instead of creating a new identity, the birth of an
	// additional device of that identity.
	RestoreFrom string `json:"restore_from,omitempty"`
	Lang                   string `json:"lang"`
	// Config, if present, overrides config.json fields (same names and
	// formats) for this instance, e.g. shorter probe/retry timers so a
	// test doesn't wait for production intervals. Applied on every start
	// and saved to config.json.
	Config json.RawMessage `json:"config,omitempty"`
}

func init() {
	agentMain = runAgent
}

// runAgent starts a normal session (same runMain as the interactive
// one) with the terminal replaced by the agent driver: the keystore is
// created or unlocked from --creds, and the TUI is driven through the
// Unix socket --sock (see internal/client/tui/agent_neutrino_agent.go).
// XDG_CONFIG_HOME must be set explicitly, so an agent instance never
// touches the default ~/.config/neutrino by accident.
func runAgent(args []string, bridgesFile, netFlag string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	sock := fs.String("sock", "", "Unix socket path for the agent protocol (required)")
	credsPath := fs.String("creds", "", "JSON credentials file, mode 0600 (required)")
	loopbackDir := fs.String("loopback-dir", "", "directory shared by every instance of the run (required with --net loopback)")
	exportBackup := fs.String("export-backup", "", "write the identity's 24 words and backup file to this directory and exit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: XDG_CONFIG_HOME=<dir> neutrino agent --sock <path> --creds <file> [--net tor|i2p|loopback] [--loopback-dir <dir>]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *exportBackup != "" && *credsPath != "" {
		creds, err := loadAgentCreds(*credsPath)
		if err != nil {
			fatal(err.Error())
		}
		if err := agentExportBackup(*exportBackup, creds); err != nil {
			fatal("agent: " + err.Error())
		}
		return
	}
	if *sock == "" || *credsPath == "" {
		fs.Usage()
		os.Exit(2)
	}
	if os.Getenv("XDG_CONFIG_HOME") == "" {
		fatal("agent: XDG_CONFIG_HOME must be set to a dedicated directory")
	}

	creds, err := loadAgentCreds(*credsPath)
	if err != nil {
		fatal(err.Error())
	}

	kind, err := transport.ParseKind(netFlag)
	if err != nil {
		fatal(err.Error())
	}
	if kind == transport.KindLoopback {
		if *loopbackDir == "" {
			fatal("agent: --net loopback requires --loopback-dir")
		}
		transport.SetLoopbackDir(*loopbackDir)
		if err := indoor.UseLoopback(*loopbackDir); err != nil {
			fatal("agent: " + err.Error())
		}
	}

	// Unix socket paths are limited to ~108 bytes: a relative --sock
	// (resolved against the working directory, which never changes)
	// keeps instances usable under long temporary directories.
	tui.EnableAgent(*sock)

	agentSession = func(ksPath, cfgPath string) (*keystore.UnlockedSlot, config.Config) {
		return agentOpenSession(ksPath, cfgPath, creds)
	}
	runMain(bridgesFile, netFlag)
}

func loadAgentCreds(path string) (agentCreds, error) {
	var c agentCreds
	st, err := os.Stat(path)
	if err != nil {
		return c, fmt.Errorf("agent: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return c, fmt.Errorf("agent: %s must not be readable by group/others (chmod 600)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("agent: %w", err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("agent: %s: %w", path, err)
	}
	if c.Username == "" || c.PasswordFile == "" || c.PasswordIdentity == "" {
		return c, errors.New("agent: username, password_file and password_identity are required")
	}
	if c.DuressUsername == "" {
		c.DuressUsername = c.Username + "-duress"
	}
	if c.DuressPasswordIdentity == "" {
		c.DuressPasswordIdentity = c.PasswordIdentity + "-duress"
	}
	if c.DuressPasswordIdentity == c.PasswordIdentity {
		return c, errors.New("agent: duress_password_identity must differ from password_identity")
	}
	if c.DeviceLabel == "" {
		c.DeviceLabel = "agent"
	}
	return c, nil
}

// agentOpenSession is the non-interactive counterpart of runOnce's
// wizard/login branch: same keystore and config functions, inputs from
// creds instead of the terminal.
func agentOpenSession(ksPath, cfgPath string, creds agentCreds) (*keystore.UnlockedSlot, config.Config) {
	var session *keystore.UnlockedSlot
	var cfg config.Config
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		lang := i18n.ParseLang(creds.Lang)
		i18n.SetActive(lang)
		if err := os.MkdirAll(filepath.Dir(ksPath), 0o700); err != nil {
			fatal(err.Error())
		}
		var ks *keystore.Keystore
		var err error
		if creds.RestoreFrom != "" {
			ks, err = agentRestore(creds.RestoreFrom)
		} else {
			qrPath := filepath.Join(filepath.Dir(ksPath), fmt.Sprintf("identity-qr-%s.png", creds.Username))
			ks, err = createIdentity(creds.Username, qrPath)
		}
		if err != nil {
			fatal(err.Error())
		}
		session, cfg = createKeystoreFile(ksPath, cfgPath, lang, ks, creds.DeviceLabel, creds.DuressUsername, creds.PasswordFile, creds.PasswordIdentity, creds.DuressPasswordIdentity)
	} else {
		var err error
		cfg, err = config.Load(cfgPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", err))
		}
		i18n.SetActive(i18n.ParseLang(cfg.Lang))
		session = openKeystoreSession(ksPath, creds.PasswordFile, creds.PasswordIdentity)
	}
	if len(creds.Config) > 0 {
		if err := json.Unmarshal(creds.Config, &cfg); err != nil {
			fatal("agent: config overrides: " + err.Error())
		}
		if err := config.Save(cfgPath, cfg); err != nil {
			fatal("agent: saving config: " + err.Error())
		}
	}
	return session, cfg
}

// Files written by --export-backup and read back by restore_from.
const (
	agentBackupWords = "words.txt"
	agentBackupFile  = "backup.bin"
)

// agentExportBackup writes the identity's 24 words and full backup file
// to dir, the non-interactive counterpart of "neutrino backup".
func agentExportBackup(dir string, creds agentCreds) error {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		return err
	}
	ks := openKeystoreSession(ksPath, creds.PasswordFile, creds.PasswordIdentity).Identity
	words, err := ks.Mnemonic()
	if err != nil {
		return err
	}
	data, err := ks.ExportBackupFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, agentBackupWords), []byte(strings.Join(words, " ")), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, agentBackupFile), data, 0o600)
}

// agentRestore rebuilds an identity from a directory written by
// agentExportBackup, the non-interactive counterpart of "neutrino
// restore" with words and backup file.
func agentRestore(dir string) (*keystore.Keystore, error) {
	words, err := os.ReadFile(filepath.Join(dir, agentBackupWords))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, agentBackupFile))
	if err != nil {
		return nil, err
	}
	return keystore.ImportFromBackupFile(strings.Fields(string(words)), data)
}
