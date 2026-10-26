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

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// binPath is the neutrino binary built once with -tags=neutrino_agent by
// TestMain and shared by every scenario. With NEUTRINO_E2E_RACE=1 it is
// built with -race too: data races inside the real application, under
// real multi-instance traffic, then fail the scenario that triggers them.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ne2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "neutrino")
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "go env GOMOD:", err)
		os.Exit(1)
	}
	args := []string{"build", "-tags=neutrino_agent", "-o", binPath}
	if os.Getenv("NEUTRINO_E2E_RACE") == "1" {
		args = append(args, "-race")
	}
	build := exec.Command("go", append(args, "./cmd/")...)
	build.Dir = filepath.Dir(strings.TrimSpace(string(gomod)))
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building the agent binary:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Timeouts for operations that are fast on loopback; generous enough
// for a loaded machine running -race.
const (
	shortWait = 15 * time.Second
	longWait  = 60 * time.Second
)

// FastTimers shortens the periodic timers that would otherwise make a
// scenario wait for production intervals (probe cycle 1m, retries 20s).
// Applied by default; a scenario that must run with production timing
// sets Run.Config = nil before starting its instances.
var FastTimers = map[string]any{
	"active_interval":      "5s",
	"active_initial_delay": "2s",
	"probe_retry_delay":    "2s",
	"knock_retry_delay":    "5s",
	"message_retry_delay":  "5s",
}

// Run is one scenario's set of instances, sharing a loopback directory.
type Run struct {
	t         *testing.T
	dir       string
	loopDir   string
	instances []*Instance

	// Config overrides config.json for every instance started afterward
	// (same field names as config.json).
	Config map[string]any
}

// NewRun creates the scenario's directories. Socket paths are limited to
// ~108 bytes, so the base directory comes from os.MkdirTemp (short),
// not t.TempDir (which embeds the test name).
func NewRun(t *testing.T) *Run {
	t.Helper()
	dir, err := os.MkdirTemp("", "ne2e-")
	if err != nil {
		t.Fatal(err)
	}
	r := &Run{t: t, dir: dir, loopDir: filepath.Join(dir, "loopback"), Config: FastTimers}
	t.Cleanup(r.cleanup)
	return r
}

func (r *Run) cleanup() {
	for _, in := range r.instances {
		if r.t.Failed() {
			in.dumpDiagnostics()
		}
		in.kill()
		if data, _ := os.ReadFile(filepath.Join(in.Dir, "out.log")); strings.Contains(string(data), "WARNING: DATA RACE") {
			r.t.Errorf("%s: data race reported, see %s", in.Name, filepath.Join(in.Dir, "out.log"))
		}
	}
	if !r.t.Failed() {
		os.RemoveAll(r.dir)
	} else {
		r.t.Logf("instance directories kept in %s", r.dir)
	}
}

// Instance is one running neutrino process in agent mode.
type Instance struct {
	t    *testing.T
	Name string
	Dir  string
	run  *Run

	cmd  *exec.Cmd
	done chan struct{}

	mu   sync.Mutex
	conn net.Conn
	rd   *bufio.Reader
}

// Start launches a new identity name (first run: keystore created from
// the credentials file) and connects to its agent socket.
func (r *Run) Start(name string) *Instance {
	r.t.Helper()
	return r.StartAs(name, name)
}

// StartAs is Start for an identity whose username is name, kept in its
// own directory dir — several instances can share the same username,
// each with its own identity key.
func (r *Run) StartAs(dir, name string) *Instance {
	r.t.Helper()
	in := &Instance{t: r.t, Name: name, Dir: filepath.Join(r.dir, dir), run: r}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	creds := map[string]any{
		"username":          name,
		"password_file":     "pf-" + name,
		"password_identity": "pi-" + name,
		"device_label":      name + "-device",
		"lang":              "en",
	}
	if r.Config != nil {
		creds["config"] = r.Config
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(in.Dir, "creds.json"), data, 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.instances = append(r.instances, in)
	in.launch()
	return in
}

// StartSibling launches a second device of of's identity, named name in
// the run: of's 24 words and backup file are exported and the new
// instance's keystore is restored from them, as "neutrino restore" does.
func (r *Run) StartSibling(of *Instance, name string) *Instance {
	r.t.Helper()
	backupDir := filepath.Join(r.dir, "backup-"+of.Name)
	export := exec.Command(binPath, "--net", "loopback", "agent", "--creds", "creds.json", "--export-backup", backupDir)
	export.Dir = of.Dir
	export.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(of.Dir, "cfg"),
		"HOME="+of.Dir,
	)
	if out, err := export.CombinedOutput(); err != nil {
		r.t.Fatalf("exporting %s's backup: %v\n%s", of.Name, err, out)
	}

	in := &Instance{t: r.t, Name: name, Dir: filepath.Join(r.dir, name), run: r}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	creds := map[string]any{
		"username":          of.Name,
		"password_file":     "pf-" + name,
		"password_identity": "pi-" + name,
		"device_label":      name + "-device",
		"lang":              "en",
		"restore_from":      backupDir,
	}
	if r.Config != nil {
		creds["config"] = r.Config
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(in.Dir, "creds.json"), data, 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.instances = append(r.instances, in)
	in.launch()
	return in
}

func (in *Instance) sockPath() string { return filepath.Join(in.Dir, "sock") }

func (in *Instance) launch() {
	in.t.Helper()
	// A killed process leaves its socket behind; the agent refuses to
	// reuse an existing path.
	_ = os.Remove(in.sockPath())
	logf, err := os.OpenFile(filepath.Join(in.Dir, "out.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		in.t.Fatal(err)
	}
	cmd := exec.Command(binPath, "--net", "loopback", "agent",
		"--sock", "sock", "--creds", "creds.json", "--loopback-dir", in.run.loopDir)
	cmd.Dir = in.Dir
	cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(in.Dir, "cfg"),
		"HOME="+in.Dir,
	)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logf.Close()
		in.t.Fatal(err)
	}
	in.cmd = cmd
	in.done = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		logf.Close()
		close(in.done)
	}()

	deadline := time.Now().Add(shortWait)
	for {
		conn, err := net.Dial("unix", in.sockPath())
		if err == nil {
			in.mu.Lock()
			in.conn, in.rd = conn, bufio.NewReaderSize(conn, 1<<20)
			in.mu.Unlock()
			return
		}
		select {
		case <-in.done:
			in.t.Fatalf("%s exited during startup:\n%s", in.Name, in.logTail())
		default:
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("%s: agent socket not ready: %v\n%s", in.Name, err, in.logTail())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ── agent protocol ──────────────────────────────────────────────────────────

// Line mirrors the agent's JSON line.
type Line struct {
	Tab       string   `json:"tab"`
	N         int      `json:"n"`
	Username  string   `json:"username"`
	Text      string   `json:"text"`
	Timestamp string   `json:"timestamp"`
	System    bool     `json:"system"`
	Sig       string   `json:"sig"`
	RelTag    string   `json:"rel_tag"`
	DevTag    string   `json:"dev_tag"`
	PQC       bool     `json:"pqc"`
	GSeq      uint64   `json:"gseq"`
	ReplyTo   uint64   `json:"reply_to"`
	AckedBy   []string `json:"acked_by"`
}

// Tab mirrors the agent's JSON tab summary.
type Tab struct {
	Index  int      `json:"index"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Lines  int      `json:"lines"`
	Unread int      `json:"unread"`
	Users  []string `json:"users"`
}

// State mirrors the agent's "state" reply.
type State struct {
	Tabs    []Tab  `json:"tabs"`
	Active  string `json:"active"`
	Input   string `json:"input"`
	Palette bool   `json:"palette"`
	PwdMode int    `json:"pwd_mode"`
	Locked  bool   `json:"locked"`
}

// Room returns the tab named name, if present.
func (s State) Room(name string) (Tab, bool) {
	for _, t := range s.Tabs {
		if t.Name == name {
			return t, true
		}
	}
	return Tab{}, false
}

// try sends one request and decodes the reply into out (may be nil).
func (in *Instance) try(req map[string]any, out any) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.conn == nil {
		if in.Exited() {
			return fmt.Errorf("%s: process exited", in.Name)
		}
		conn, err := net.Dial("unix", in.sockPath())
		if err != nil {
			return fmt.Errorf("%s: %w", in.Name, err)
		}
		in.conn, in.rd = conn, bufio.NewReaderSize(conn, 1<<20)
	}
	// After any I/O error the stream may hold a late reply: drop the
	// connection, the next request dials a fresh one.
	fail := func(err error) error {
		in.conn.Close()
		in.conn = nil
		return fmt.Errorf("%s: %w", in.Name, err)
	}
	// A paused or hung process never answers: bound every request.
	limit := shortWait + 15*time.Second
	if s, ok := req["timeout"].(float64); ok {
		limit = time.Duration(s*float64(time.Second)) + 15*time.Second
	}
	_ = in.conn.SetDeadline(time.Now().Add(limit))
	data, _ := json.Marshal(req)
	if _, err := in.conn.Write(append(data, '\n')); err != nil {
		return fail(err)
	}
	reply, err := in.rd.ReadBytes('\n')
	if err != nil {
		return fail(err)
	}
	var status struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(reply, &status); err != nil {
		return fmt.Errorf("%s: bad reply %q: %w", in.Name, reply, err)
	}
	if !status.OK {
		return fmt.Errorf("%s: %s", in.Name, status.Error)
	}
	if out != nil {
		return json.Unmarshal(reply, out)
	}
	return nil
}

func (in *Instance) do(req map[string]any, out any) {
	in.t.Helper()
	if err := in.try(req, out); err != nil {
		in.t.Fatal(err)
	}
}

// Send types text and presses Enter.
func (in *Instance) Send(text string) {
	in.t.Helper()
	in.do(map[string]any{"cmd": "send", "text": text}, nil)
}

// Type types text without Enter.
func (in *Instance) Type(text string) {
	in.t.Helper()
	in.do(map[string]any{"cmd": "type", "text": text}, nil)
}

// Key presses one named key (enter, esc, tab, up, down, ...).
func (in *Instance) Key(k string) {
	in.t.Helper()
	in.do(map[string]any{"cmd": "key", "key": k}, nil)
}

// State returns tabs, active tab and input line.
func (in *Instance) State() State {
	in.t.Helper()
	var s State
	in.do(map[string]any{"cmd": "state"}, &s)
	return s
}

// Lines returns the lines of tab ("" = active) from index from.
func (in *Instance) Lines(tab string, from int) []Line {
	in.t.Helper()
	var r struct {
		Lines []Line `json:"lines"`
	}
	in.do(map[string]any{"cmd": "lines", "tab": tab, "from": from}, &r)
	return r.Lines
}

// LineCount returns how many lines tab currently holds — the "from"
// to pass to a later Wait so it only matches what happens afterward.
func (in *Instance) LineCount(tab string) int {
	in.t.Helper()
	for _, t := range in.State().Tabs {
		if t.Name == tab {
			return t.Lines
		}
	}
	return 0
}

// Screen returns the rendered screen, ANSI stripped.
func (in *Instance) Screen() string {
	in.t.Helper()
	var r struct {
		Screen string `json:"screen"`
	}
	in.do(map[string]any{"cmd": "screen"}, &r)
	return r.Screen
}

// Wait waits for a line of tab ("*" = any tab) from index from whose
// "username: text" (or text alone, for lines without a username)
// matches pattern.
func (in *Instance) Wait(tab, pattern string, from int, timeout time.Duration) Line {
	in.t.Helper()
	var r struct {
		Line Line `json:"line"`
	}
	err := in.try(map[string]any{
		"cmd": "wait", "tab": tab, "pattern": pattern, "from": from,
		"timeout": timeout.Seconds(),
	}, &r)
	if err != nil {
		in.t.Fatalf("%v\n--- screen of %s ---\n%s", err, in.Name, in.screenOrErr())
	}
	return r.Line
}

// WaitScreen waits until the rendered screen matches pattern.
func (in *Instance) WaitScreen(pattern string, timeout time.Duration) {
	in.t.Helper()
	in.WaitScreenMatch(pattern, timeout)
}

// WaitScreenMatch waits until the rendered screen matches pattern and
// returns the match with its submatches.
func (in *Instance) WaitScreenMatch(pattern string, timeout time.Duration) []string {
	in.t.Helper()
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(timeout)
	for {
		s := in.Screen()
		if sub := re.FindStringSubmatch(s); sub != nil {
			return sub
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("%s: timeout waiting for screen %q\n--- screen ---\n%s", in.Name, pattern, s)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// WaitUsers waits until the tab room lists exactly the given users.
func (in *Instance) WaitUsers(room string, users []string, timeout time.Duration) {
	in.t.Helper()
	want := slices.Clone(users)
	slices.Sort(want)
	deadline := time.Now().Add(timeout)
	for {
		var got []string
		if t, ok := in.State().Room(room); ok {
			got = slices.Clone(t.Users)
			slices.Sort(got)
			if slices.Equal(got, want) {
				return
			}
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("%s: room %s users = %v, want %v\n--- screen ---\n%s", in.Name, room, got, want, in.screenOrErr())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Contact mirrors the agent's address book entry.
type Contact struct {
	Username       string `json:"username"`
	LocalName      string `json:"local_name"`
	NetAddr        string `json:"net_addr"`
	Verified       bool   `json:"verified"`
	IntroducedBy   string `json:"introduced_by"`
	Devices        int    `json:"devices"`
	ReadyDevices   int    `json:"ready_devices"`
	RelEstablished bool   `json:"rel_established"`
	RelRevoked     bool   `json:"rel_revoked"`
}

// Contacts returns the address book.
func (in *Instance) Contacts() []Contact {
	in.t.Helper()
	var r struct {
		Contacts []Contact `json:"contacts"`
	}
	in.do(map[string]any{"cmd": "contacts"}, &r)
	return r.Contacts
}

// WaitContact waits until the contact username satisfies cond.
func (in *Instance) WaitContact(username string, cond func(Contact) bool, what string, timeout time.Duration) Contact {
	in.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var last *Contact
		for _, c := range in.Contacts() {
			if c.Username == username {
				last = &c
				if cond(c) {
					return c
				}
			}
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("%s: contact %s never %s (last state: %+v)", in.Name, username, what, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// WaitReady waits until both relationship keys toward username are
// confirmed by the peer — the precondition for inviting them.
func (in *Instance) WaitReady(username string) {
	in.t.Helper()
	in.WaitContact(username, func(c Contact) bool { return c.ReadyDevices > 0 }, "ready", longWait)
}

func (in *Instance) screenOrErr() string {
	var r struct {
		Screen string `json:"screen"`
	}
	if err := in.try(map[string]any{"cmd": "screen"}, &r); err != nil {
		return "(screen unavailable: " + err.Error() + ")"
	}
	return r.Screen
}

// URI returns the identity URI written at keystore creation.
func (in *Instance) URI() string {
	in.t.Helper()
	data, err := os.ReadFile(filepath.Join(in.Dir, "cfg", "neutrino", "identity-qr-"+in.Name+".txt"))
	if err != nil {
		in.t.Fatal(err)
	}
	uri := regexp.MustCompile(`nu://\S+`).Find(data)
	if uri == nil {
		in.t.Fatalf("%s: no nu:// URI in the identity file", in.Name)
	}
	return string(uri)
}

// ── process control ─────────────────────────────────────────────────────────

// Pause freezes the process (SIGSTOP): connections stay open, nothing is
// read or written — the same as a phone suspending the app.
func (in *Instance) Pause() {
	in.t.Helper()
	if err := in.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		in.t.Fatal(err)
	}
}

// Resume restarts a paused process (SIGCONT).
func (in *Instance) Resume() {
	in.t.Helper()
	if err := in.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		in.t.Fatal(err)
	}
}

// Kill terminates the process abruptly (SIGKILL), as a crash would.
func (in *Instance) Kill() {
	in.t.Helper()
	in.kill()
}

func (in *Instance) kill() {
	in.mu.Lock()
	if in.conn != nil {
		in.conn.Close()
		in.conn = nil
	}
	in.mu.Unlock()
	if in.cmd != nil && in.cmd.Process != nil {
		_ = in.cmd.Process.Signal(syscall.SIGCONT)
		_ = in.cmd.Process.Kill()
		<-in.done
	}
}

// Restart starts the same identity again (login on the existing keystore).
func (in *Instance) Restart() {
	in.t.Helper()
	in.kill()
	in.launch()
}

// Quit runs /quit, confirms, and waits for the process to exit.
func (in *Instance) Quit() {
	in.t.Helper()
	in.Send("/quit")
	in.WaitScreen(`Quit\? \[y/n\]`, shortWait)
	// The program may end, closing the connection, before replying:
	// the process exit below is what counts.
	_ = in.try(map[string]any{"cmd": "type", "text": "y"}, nil)
	select {
	case <-in.done:
	case <-time.After(shortWait):
		in.t.Fatalf("%s: still running after /quit", in.Name)
	}
	in.mu.Lock()
	if in.conn != nil {
		in.conn.Close()
		in.conn = nil
	}
	in.mu.Unlock()
}

// Exited reports whether the process has terminated.
func (in *Instance) Exited() bool {
	select {
	case <-in.done:
		return true
	default:
		return false
	}
}

func (in *Instance) logTail() string {
	data, _ := os.ReadFile(filepath.Join(in.Dir, "out.log"))
	if len(data) > 4000 {
		data = data[len(data)-4000:]
	}
	return string(data)
}

func (in *Instance) dumpDiagnostics() {
	in.t.Logf("=== %s: out.log tail ===\n%s", in.Name, in.logTail())
	if in.Exited() {
		return
	}
	var r struct {
		Lines []Line `json:"lines"`
	}
	if err := in.try(map[string]any{"cmd": "lines", "tab": "Console"}, &r); err == nil {
		var sb strings.Builder
		for _, l := range r.Lines {
			fmt.Fprintf(&sb, "%d %s %s\n", l.N, l.Username, l.Text)
		}
		in.t.Logf("=== %s: Console ===\n%s", in.Name, sb.String())
	}
	in.t.Logf("=== %s: screen ===\n%s", in.Name, in.screenOrErr())
}

// ── common flows ────────────────────────────────────────────────────────────

// AddContact makes a add b through /cnt-add with b's URI, confirming the
// summary and keeping the default local name.
func AddContact(a, b *Instance) {
	a.t.Helper()
	from := a.LineCount("Console")
	a.Send("/cnt-add " + b.URI())
	a.WaitScreen(`Save this contact\? \[Y/n\]`, shortWait)
	a.Key("enter")
	a.WaitScreen(`Local name \[default: `+regexp.QuoteMeta(b.Name)+`\]`, shortWait)
	a.Key("enter")
	a.Wait("Console", `contact added: `+regexp.QuoteMeta(b.Name), from, shortWait)
}

// Pair makes a and b mutual contacts and waits until the relationship
// key exchange is confirmed on both sides.
func Pair(a, b *Instance) {
	a.t.Helper()
	AddContact(a, b)
	AddContact(b, a)
	a.t.Logf("%s and %s: contacts added", a.Name, b.Name)
	a.WaitReady(b.Name)
	b.WaitReady(a.Name)
	a.t.Logf("%s and %s: relationship keys confirmed", a.Name, b.Name)
}

// OpenRoom has host invite members with /grp-invite, each member accepts
// the invite popup, and waits until every participant — host included —
// has the room tab listing all of them. Returns the room's tab name.
func OpenRoom(host *Instance, members ...*Instance) string {
	host.t.Helper()
	names := []string{host.Name}
	for _, m := range members {
		names = append(names, m.Name)
	}
	host.Send("/grp-invite " + strings.Join(names[1:], " "))
	room := ""
	for _, m := range members {
		sub := m.WaitScreenMatch(regexp.QuoteMeta(host.Name)+` invites you to group (\w+)`, longWait)
		if room == "" {
			room = sub[1]
		} else if sub[1] != room {
			host.t.Fatalf("%s was invited to group %s, %s to group %s", members[0].Name, room, m.Name, sub[1])
		}
		m.Key("enter")
	}
	host.t.Logf("room %s: invite accepted by %v", room, names[1:])
	for _, in := range append([]*Instance{host}, members...) {
		in.WaitUsers(room, names, longWait)
	}
	host.t.Logf("room %s: all members connected", room)
	return room
}

// Focus switches the active tab to name by pressing Tab, as a person
// would.
func (in *Instance) Focus(name string) {
	in.t.Helper()
	s := in.State()
	for range s.Tabs {
		if s.Active == name {
			return
		}
		in.Key("tab")
		s = in.State()
	}
	if s.Active != name {
		in.t.Fatalf("%s: no tab %q (tabs: %+v)", in.Name, name, s.Tabs)
	}
}
