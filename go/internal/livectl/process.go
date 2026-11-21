package livectl

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// MaxRunSeconds: no run outlives this, whatever the client asked or did (stage 6, A08).
const MaxRunSeconds = 600

const maxLine = 131072 // bytes of one worker line

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// Worker builds the worker process of a run: the Go binary's `live` (or `live-decrypt` with a key log), the
// commands the reference's workers hand over to.
type Worker func(iface, filter string, duration int64, decrypt bool) []string

// Manager is LiveManager: the run state plus its worker process.
type Manager struct {
	*State
	Token   string
	worker  Worker
	lookTcp func() bool
	ifaces  func() []string

	process *exec.Cmd
	exited  chan struct{} // closed when the process has been reaped
	reading bool          // the reader is still running (the reference's thread.is_alive())
	stopMu  sync.Mutex
}

// NewManager is LiveManager().
func NewManager(worker Worker) *Manager {
	return &Manager{State: NewState(nil), Token: tokenURLSafe(32), worker: worker,
		lookTcp: func() bool { _, err := exec.LookPath("tcpdump"); return err == nil },
		ifaces:  systemInterfaces}
}

func tokenURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func systemInterfaces() []string {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, i := range list {
		if interfaceName.MatchString(i.Name) {
			out = append(out, i.Name)
		}
	}
	return out
}

// Interfaces is interfaces().
func (m *Manager) Interfaces() *ojson.Object {
	names := []ojson.Value{}
	for _, n := range m.ifaces() {
		names = append(names, n)
	}
	return ojson.NewObject("interfaces", names, "available", m.lookTcp(), "token", m.Token)
}

// alive is `process is not None and process.poll() is None` (the lock is held).
func (m *Manager) alive() bool {
	if m.process == nil {
		return false
	}
	select {
	case <-m.exited:
		return false
	default:
		return true
	}
}

// StartError is the reference's ValueError from start(); the server answers 400 with its text.
type StartError struct{ Message string }

func (e *StartError) Error() string { return e.Message }

func isInt(v ojson.Value) (int64, bool) {
	i, ok := v.(ojson.Int)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(i), 10, 64)
	if err != nil {
		return 1 << 62, true // an int the reference compares and refuses as out of range
	}
	return n, true
}

// Start is start(interface, duration, scope, keylog_path) with the request's decoded values.
func (m *Manager) Start(ifaceValue, durationValue, scopeValue, keylogValue ojson.Value) (*ojson.Object, error) {
	m.mu.Lock()
	if m.alive() {
		m.mu.Unlock()
		return nil, &StartError{"A live capture is already running."}
	}
	if m.reading {
		m.mu.Unlock()
		return nil, &StartError{"Previous capture is still stopping."}
	}
	iface, ok := ifaceValue.(string)
	known := false
	if ok {
		for _, n := range m.ifaces() {
			known = known || n == iface
		}
	}
	if !known || (len(iface) > 0 && iface[0] == '-') {
		m.mu.Unlock()
		return nil, &StartError{"Select an available network interface."}
	}
	duration, ok := isInt(durationValue)
	if !ok || duration < 5 || duration > 600 {
		m.mu.Unlock()
		return nil, &StartError{"Duration must be 5–600 seconds."}
	}
	scope, _ := scopeValue.(string)
	if scope != "all" && scope != "synthetic" {
		m.mu.Unlock()
		return nil, &StartError{"Invalid capture scope."}
	}
	if scope == "synthetic" && iface != "lo0" && iface != "lo" {
		m.mu.Unlock()
		return nil, &StartError{"Local synthetic capture requires lo0 or lo."}
	}
	if !m.lookTcp() {
		m.mu.Unlock()
		return nil, &StartError{"tcpdump is not installed on this computer."}
	}
	keylog := ""
	decrypt := keylogValue != nil
	if decrypt {
		path, ok := keylogValue.(string)
		if !ok || len(path) == 0 || path[0] != '/' || utf8.RuneCountInString(path) > 1024 {
			m.mu.Unlock()
			return nil, &StartError{"Enter the absolute path of the browser key log."}
		}
		if duration > 120 {
			m.mu.Unlock()
			return nil, &StartError{"Live decryption is limited to 120 seconds per sample."}
		}
		keylog = path
	}
	// Exclude the dashboard itself to avoid capturing its polling traffic.
	filter := "(tcp or udp) and not (host 127.0.0.1 and tcp portrange 8765-8775)"
	if scope == "synthetic" {
		filter = "host 127.0.0.1 and tcp port 45991"
	}
	argv := m.worker(iface, filter, duration, decrypt)
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	previous := m.phase
	m.begin(hex.EncodeToString(id), iface)
	m.phase = previous // the reference sets "running" only once the process has started
	process := exec.Command(argv[0], argv[1:]...)
	ownSession(process) // its own session: the process group to kill
	process.Stderr = nil
	reader, writer, err := os.Pipe()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	process.Stdout = writer
	var stdin io.WriteCloser
	if decrypt {
		stdin, err = process.StdinPipe()
		if err != nil {
			reader.Close()
			writer.Close()
			m.mu.Unlock()
			return nil, err
		}
	}
	if err := process.Start(); err != nil {
		reader.Close()
		writer.Close()
		m.mu.Unlock()
		return nil, err
	}
	writer.Close()
	m.process, m.exited = process, make(chan struct{})
	exited := m.exited
	go func() {
		_ = process.Wait()
		close(exited)
	}()
	if decrypt {
		line := ojson.MustDumps(ojson.NewObject("keylog_path", keylog)) + "\n"
		_, _ = io.WriteString(stdin, line)
		stdin.Close()
	}
	m.phase = "running"
	m.reading = true
	m.mu.Unlock()
	go m.read(process, exited, reader)
	go m.watch(process, exited, duration)
	return m.Snapshot(), nil
}

// read is _read: one JSON object per line, each ingested; any failure is the run's error and stops it.
func (m *Manager) read(process *exec.Cmd, exited chan struct{}, pipe *os.File) {
	in := bufio.NewReaderSize(pipe, 65536)
	failed := func(text string) {
		m.mu.Lock()
		m.errorText = text
		m.mu.Unlock()
		m.Stop(nil, nil)
	}
	finish := func() {
		pipe.Close()
		m.mu.Lock()
		m.reading = false
		if m.errorText != nil {
			m.phase = "failed"
		} else {
			m.phase = "stopped"
		}
		m.mu.Unlock()
	}
	defer finish()
	for {
		line, err := readLine(in)
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil && err != io.EOF {
			failed(err.Error())
			return
		}
		if len(line) > maxLine || line[len(line)-1] != '\n' {
			failed("Live metadata exceeded its size limit.")
			return
		}
		v, derr := ojson.Decode(line)
		if derr != nil {
			// The reference publishes json.loads' message (with its line and column); a worker never writes such
			// a line, so the text is this port's own.
			failed("Live metadata could not be decoded: " + derr.Error())
			return
		}
		event, ok := v.(*ojson.Object)
		if !ok {
			// The reference's reader dies on a line that is not an object (AttributeError) and closes the pipe;
			// the run ends as stopped and the watcher stops the worker. The same here.
			return
		}
		m.Ingest(event)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		failed("Capture process did not exit after closing its output.")
		return
	}
	code := exitCode(process)
	m.mu.Lock()
	if code != 0 && code != 2 && m.errorText == nil {
		m.errorText = "Capture process exited unexpectedly (" + strconv.Itoa(code) + ")."
	}
	m.mu.Unlock()
}

// readLine is readline(131073): at most maxLine+1 bytes, ending at the first newline.
func readLine(in *bufio.Reader) ([]byte, error) {
	var line []byte
	for len(line) <= maxLine {
		b, err := in.ReadByte()
		if err != nil {
			return line, err
		}
		line = append(line, b)
		if b == '\n' {
			return line, nil
		}
	}
	return line, nil
}

func exitCode(process *exec.Cmd) int {
	if process.ProcessState == nil {
		return -1
	}
	if ws, ok := process.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return process.ProcessState.ExitCode()
}

// watch is _watch: the server-enforced lifetime and the dashboard lease.
func (m *Manager) watch(process *exec.Cmd, exited chan struct{}, duration int64) {
	limit := duration
	if limit > MaxRunSeconds {
		limit = MaxRunSeconds
	}
	deadline := time.Now().Add(time.Duration(limit+5) * time.Second)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-exited:
			return
		case <-ticker.C:
		}
		m.mu.Lock()
		expired := m.now().Sub(m.lease) > leaseWindow*time.Second
		m.mu.Unlock()
		if expired || time.Now().After(deadline) {
			m.Stop(process, nil)
			return
		}
	}
}

// Stop is stop(expected, run_id): idempotent; stopping a stopped run, or naming another run, changes nothing.
func (m *Manager) Stop(expected *exec.Cmd, runID ojson.Value) {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()
	m.mu.Lock()
	process, exited := m.process, m.exited
	if expected != nil && process != expected {
		m.mu.Unlock()
		return
	}
	if runID != nil && !m.runMatches(runID) {
		m.mu.Unlock()
		return
	}
	if process == nil || !m.alive() {
		m.mu.Unlock()
		return
	}
	m.phase = "stopping"
	if err := process.Process.Signal(os.Interrupt); err != nil {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		killGroup(process) // only this run's process group
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}
}

// Heartbeat is heartbeat(run_id): the one call that renews the lease, for the run it names.
func (m *Manager) Heartbeat(runID ojson.Value) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if runID != nil && m.runMatches(runID) && m.alive() {
		m.lease = m.now()
		return true
	}
	return false
}

// Reset is reset(run_id): stops the named run if it still runs and clears everything it retained.
func (m *Manager) Reset(runID ojson.Value) *ojson.Object {
	m.mu.Lock()
	if runID == nil || !m.runMatches(runID) {
		defer m.mu.Unlock()
		return m.staleReset(runID)
	}
	running := m.alive()
	m.mu.Unlock()
	if running {
		m.Stop(nil, runID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.runMatches(runID) {
		return ojson.NewObject("reset", false, "reason", "stale", "run_id", m.captureID)
	}
	return m.clear()
}
