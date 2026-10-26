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

package tui

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// Agent mode drives the real TUI model without a terminal: a local Unix
// socket accepts one JSON request per line and answers one JSON object
// per line. Keystrokes are injected into the bubbletea program exactly
// as a keyboard would deliver them; state is read from inside the
// bubbletea loop (agentQueryMsg), never from a copy taken elsewhere.
//
// Requests ("cmd" field):
//
//	type   {text}             types text into the input, no Enter
//	send   {text}             types text, then Enter
//	key    {key}              one named key (enter, esc, tab, shift+tab,
//	                          up, down, left, right, space, backspace,
//	                          delete, home, end, pgup, pgdown, ctrl+c)
//	state  {}                 tabs, active tab, input line, open modes
//	lines  {tab, from}        lines of a tab ("" = active) from index from
//	screen {}                 the rendered screen, ANSI stripped
//	contacts {}               address book with relationship state
//	wait   {tab, pattern, from, timeout}
//	                          waits for a line of tab ("*" = any tab)
//	                          matching the regexp pattern, from index from,
//	                          timeout in seconds (default 30)
//
// Replies: {"ok":true,...} or {"ok":false,"error":"..."}.

const (
	agentScreenWidth  = 160
	agentScreenHeight = 50
	agentQueryTimeout = 10 * time.Second
)

// EnableAgent switches RunTUI to agent mode, listening on sockPath.
func EnableAgent(sockPath string) {
	agent = &agentHooks{
		options: func() []tea.ProgramOption {
			return []tea.ProgramOption{
				tea.WithInput(nil),
				tea.WithOutput(io.Discard),
				tea.WithoutRenderer(),
			}
		},
		attach: func(p *tea.Program) (func(), error) {
			return serveAgent(p, sockPath)
		},
	}
}

type agentRequest struct {
	Cmd     string  `json:"cmd"`
	Text    string  `json:"text,omitempty"`
	Key     string  `json:"key,omitempty"`
	Tab     string  `json:"tab,omitempty"`
	From    int     `json:"from,omitempty"`
	Pattern string  `json:"pattern,omitempty"`
	Timeout float64 `json:"timeout,omitempty"`
}

type agentLine struct {
	Tab       string   `json:"tab"`
	N         int      `json:"n"`
	Username  string   `json:"username,omitempty"`
	Text      string   `json:"text"`
	Timestamp string   `json:"timestamp,omitempty"`
	System    bool     `json:"system,omitempty"`
	Sig       string   `json:"sig,omitempty"`
	RelTag    string   `json:"rel_tag,omitempty"`
	DevTag    string   `json:"dev_tag,omitempty"`
	PQC       bool     `json:"pqc,omitempty"`
	GSeq      uint64   `json:"gseq,omitempty"`
	ReplyTo   uint64   `json:"reply_to,omitempty"`
	AckedBy   []string `json:"acked_by,omitempty"`
}

type agentTab struct {
	Index  int      `json:"index"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Lines  int      `json:"lines"`
	Unread int      `json:"unread,omitempty"`
	Users  []string `json:"users,omitempty"`
}

var agentKeys = map[string]tea.KeyType{
	"enter":     tea.KeyEnter,
	"esc":       tea.KeyEsc,
	"tab":       tea.KeyTab,
	"shift+tab": tea.KeyShiftTab,
	"up":        tea.KeyUp,
	"down":      tea.KeyDown,
	"left":      tea.KeyLeft,
	"right":     tea.KeyRight,
	"space":     tea.KeySpace,
	"backspace": tea.KeyBackspace,
	"delete":    tea.KeyDelete,
	"home":      tea.KeyHome,
	"end":       tea.KeyEnd,
	"pgup":      tea.KeyPgUp,
	"pgdown":    tea.KeyPgDown,
	"ctrl+c":    tea.KeyCtrlC,
}

func serveAgent(p *tea.Program, sockPath string) (func(), error) {
	if _, err := os.Lstat(sockPath); err == nil {
		return nil, fmt.Errorf("agent: %s already exists", sockPath)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("agent: %w", err)
	}
	// Open connections belong to this program: when it ends (quit, or
	// the re-entry after a nuke) they are closed with it, so a client
	// dials the next program's socket instead of waiting on this one.
	var connMu sync.Mutex
	conns := map[net.Conn]bool{}
	closed := false
	go func() {
		// Without a terminal no WindowSizeMsg ever arrives: the model
		// needs one to build its viewport. Send blocks until the
		// program runs, so connections are accepted only afterward.
		p.Send(tea.WindowSizeMsg{Width: agentScreenWidth, Height: agentScreenHeight})
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connMu.Lock()
			if closed {
				connMu.Unlock()
				conn.Close()
				return
			}
			conns[conn] = true
			connMu.Unlock()
			go func() {
				handleAgentConn(p, conn)
				connMu.Lock()
				delete(conns, conn)
				connMu.Unlock()
			}()
		}
	}()
	return func() {
		ln.Close()
		_ = os.Remove(sockPath)
		connMu.Lock()
		closed = true
		for conn := range conns {
			conn.Close()
		}
		connMu.Unlock()
	}, nil
}

func handleAgentConn(p *tea.Program, conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		var req agentRequest
		var reply map[string]any
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			reply = map[string]any{"ok": false, "error": "invalid request: " + err.Error()}
		} else {
			reply = handleAgentRequest(p, req)
		}
		if err := enc.Encode(reply); err != nil {
			return
		}
	}
}

func handleAgentRequest(p *tea.Program, req agentRequest) map[string]any {
	res, err := agentDispatch(p, req)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if res == nil {
		res = map[string]any{}
	}
	res["ok"] = true
	return res
}

func agentDispatch(p *tea.Program, req agentRequest) (map[string]any, error) {
	switch req.Cmd {
	case "type", "send":
		if strings.ContainsAny(req.Text, "\r\n") {
			return nil, errors.New("text must not contain newlines")
		}
		if req.Text != "" {
			p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(req.Text)})
		}
		if req.Cmd == "send" {
			p.Send(tea.KeyMsg{Type: tea.KeyEnter})
		}
		// Round-trip through the loop: the reply leaves only once the
		// keystrokes above have been processed by Update.
		_, err := agentQuery(p, func(m model) struct{} { return struct{}{} })
		return nil, err

	case "key":
		k, ok := agentKeys[strings.ToLower(req.Key)]
		if !ok {
			return nil, fmt.Errorf("unknown key %q", req.Key)
		}
		p.Send(tea.KeyMsg{Type: k})
		_, err := agentQuery(p, func(m model) struct{} { return struct{}{} })
		return nil, err

	case "state":
		return agentQuery(p, agentState)

	case "lines":
		lines, err := agentQuery(p, func(m model) any {
			ls, err := agentTabLines(m, req.Tab, req.From)
			if err != nil {
				return err
			}
			return ls
		})
		if err != nil {
			return nil, err
		}
		if e, ok := lines.(error); ok {
			return nil, e
		}
		return map[string]any{"lines": lines}, nil

	case "screen":
		screen, err := agentQuery(p, func(m model) string { return ansi.Strip(m.View()) })
		if err != nil {
			return nil, err
		}
		return map[string]any{"screen": screen}, nil

	case "wait":
		return agentWait(p, req)

	case "contacts":
		contacts, err := agentQuery(p, agentContacts)
		if err != nil {
			return nil, err
		}
		return map[string]any{"contacts": contacts}, nil

	default:
		return nil, fmt.Errorf("unknown cmd %q", req.Cmd)
	}
}

// agentQuery runs fn inside the bubbletea loop and returns its result.
// Fails if the program doesn't answer in time (e.g. it already exited).
func agentQuery[T any](p *tea.Program, fn func(m model) T) (T, error) {
	ch := make(chan T, 1)
	go p.Send(agentQueryMsg{fn: func(m model) { ch <- fn(m) }})
	select {
	case v := <-ch:
		return v, nil
	case <-time.After(agentQueryTimeout):
		var zero T
		return zero, errors.New("program not responding")
	}
}

func agentTabKind(t *roomTab) string {
	switch {
	case t.isConsole:
		return "console"
	case t.isContacts:
		return "contacts"
	case t.isGroups:
		return "groups"
	case t.isTor:
		return "network"
	case t.isFiles:
		return "files"
	default:
		return "room"
	}
}

type agentContact struct {
	Username       string `json:"username"`
	LocalName      string `json:"local_name,omitempty"`
	NetAddr        string `json:"net_addr,omitempty"`
	Verified       bool   `json:"verified,omitempty"`
	IntroducedBy   string `json:"introduced_by,omitempty"`
	Devices        int    `json:"devices"`
	ReadyDevices   int    `json:"ready_devices"`
	RelEstablished bool   `json:"rel_established,omitempty"`
	RelRevoked     bool   `json:"rel_revoked,omitempty"`
}

func agentContacts(m model) []agentContact {
	out := make([]agentContact, 0, len(m.contacts))
	for _, c := range m.contacts {
		_, established := c.RelEstablishedDevice()
		out = append(out, agentContact{
			Username:       c.Username,
			LocalName:      c.LocalName,
			NetAddr:        c.NetAddr,
			Verified:       c.Verified,
			IntroducedBy:   c.IntroducedBy,
			Devices:        len(c.Devices),
			ReadyDevices:   len(c.ReadyDevices()),
			RelEstablished: established,
			RelRevoked:     c.RelRevoked(),
		})
	}
	return out
}

func agentState(m model) map[string]any {
	tabs := make([]agentTab, len(m.tabs))
	for i, t := range m.tabs {
		tabs[i] = agentTab{
			Index:  i,
			Name:   t.name,
			Kind:   agentTabKind(t),
			Lines:  len(t.lines),
			Unread: t.unread,
			Users:  agentMemberNames(&m, t, t.online),
		}
	}
	active := ""
	if m.active < len(m.tabs) {
		active = m.tabs[m.active].name
	}
	return map[string]any{
		"tabs":     tabs,
		"active":   active,
		"input":    m.ta.Value(),
		"palette":  m.showPalette,
		"pwd_mode": m.pwdMode,
		"locked":   m.interfaceLocked,
	}
}

func agentFindTab(m model, name string) (*roomTab, error) {
	if name == "" {
		if m.active < len(m.tabs) {
			return m.tabs[m.active], nil
		}
		return nil, errors.New("no active tab")
	}
	for _, t := range m.tabs {
		if strings.EqualFold(t.name, name) {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no tab named %q", name)
}

func agentConvertLine(m *model, t *roomTab, n int, l chatLine) agentLine {
	tab := t.name
	out := agentLine{
		Tab:       tab,
		N:         n,
		Username:  l.username,
		Text:      ansi.Strip(l.text),
		Timestamp: l.timestamp,
		System:    l.isSystem,
		RelTag:    l.contentKeyTag,
		DevTag:    l.deviceTag,
		PQC:       l.pqcActive,
		GSeq:      l.gseq,
		ReplyTo:   l.replyTo,
	}
	switch l.sigStatus {
	case sigPending:
		out.Sig = "pending"
	case sigOK:
		out.Sig = "ok"
	case sigFailed:
		out.Sig = "failed"
	case sigOwn:
		out.Sig = "own"
	}
	ackers := make([]string, 0, len(l.ackers))
	for k := range l.ackers {
		ackers = append(ackers, k)
	}
	out.AckedBy = agentMemberNames(m, t, ackers)
	sort.Strings(out.AckedBy)
	return out
}

func agentTabLines(m model, name string, from int) ([]agentLine, error) {
	t, err := agentFindTab(m, name)
	if err != nil {
		return nil, err
	}
	if from < 0 {
		from = 0
	}
	out := []agentLine{}
	for i := from; i < len(t.lines); i++ {
		out = append(out, agentConvertLine(&m, t, i, t.lines[i]))
	}
	return out, nil
}

func agentWait(p *tea.Program, req agentRequest) (map[string]any, error) {
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	timeout := 30 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout * float64(time.Second))
	}
	deadline := time.Now().Add(timeout)
	for {
		found, err := agentQuery(p, func(m model) any {
			var tabs []*roomTab
			if req.Tab == "*" {
				tabs = m.tabs
			} else {
				t, err := agentFindTab(m, req.Tab)
				if err != nil {
					return err
				}
				tabs = []*roomTab{t}
			}
			for _, t := range tabs {
				for i := max(req.From, 0); i < len(t.lines); i++ {
					l := agentConvertLine(&m, t, i, t.lines[i])
					subject := l.Text
					if l.Username != "" {
						subject = l.Username + ": " + l.Text
					}
					if re.MatchString(subject) {
						return l
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		switch v := found.(type) {
		case error:
			// The tab may not exist yet (e.g. a room still being
			// opened): keep waiting until the deadline.
		case agentLine:
			return map[string]any{"line": v}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for %q", req.Pattern)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// agentMemberNames maps member keys to their display names, the form
// the e2e scenarios check against.
func agentMemberNames(m *model, t *roomTab, keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.memberName(t, k))
	}
	return out
}
