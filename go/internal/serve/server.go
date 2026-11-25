// Package serve ports presentation/server.py's LocalServer and Handler: the loopback-only dashboard service
// with its bounded handler pool, the live control endpoints (contracts C14, C15), admission-controlled
// analysis and decryption jobs, and the static page. Every answer is the reference's: status, body text and
// the headers it sets (Server and Date name this implementation and the time).
//
// The synthetic demo capture (/api/sample, the "demo" job), the decryption showcase (the "decrypt-demo" job) and
// the catalog export (/api/catalog) used to be answered by the reference's own code run as a Python worker; since
// PRO-401 they are this service's own (showcase.go), and the service runs no interpreter.
package serve

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/jobs"
	"github.com/leenadav/protocol-detector/go/internal/livectl"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

const (
	MaxUpload     = 8 * 1024 * 1024
	MaxDecrypt    = 12 * 1024 * 1024
	MaxHandlers   = 8
	WorkerSeconds = 25
	MaxFrames     = 20000
	MaxSessions   = 500
	MaxEvents     = 4000
)

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

// Server is LocalServer.
type Server struct {
	Root     string // the presentation directory (SOURCE.json, web/, server.py)
	Python   string // unused since PRO-401 (no reference generator is run); kept for the --python flag
	Self     string // this binary, for the workers
	Live     *livectl.Manager
	Jobs     *jobs.Runner
	listener net.Listener
	port     int
	slots    chan struct{}
	rejected atomic.Int64
	instance struct {
		sync.Mutex
		id      string
		started time.Time
	}
	catalog struct {
		sync.Mutex
		body string
	}
}

// New builds the server state (LocalServer.__init__); Listen binds it.
func New(root, python, self string) (*Server, error) {
	s := &Server{Root: root, Python: python, Self: self, slots: make(chan struct{}, MaxHandlers)}
	s.Live = livectl.NewManager(func(iface, filter string, duration int64, decrypt bool) []string {
		if decrypt {
			return []string{self, "live-decrypt", "--interface", iface, "--filter", filter, "--duration", strconv.FormatInt(duration, 10)}
		}
		return []string{self, "live", "--interface", iface, "--filter", filter, "--duration", strconv.FormatInt(duration, 10),
			"--max-packets", "100000", "--max-connections", "128", "--byte-limit", "16384", "--idle-timeout", "15",
			"--stats-interval", "1", "--all-events", "--fingerprints", "--json"}
	})
	runner, err := jobs.New(s.workerCommand, 2, 4, WorkerSeconds*time.Second, 32, 300, nil)
	if err != nil {
		return nil, err
	}
	s.Jobs = runner
	return s, nil
}

// workerCommand is worker_command(kind, payload).
func (s *Server) workerCommand(kind string, payload []byte) ([]string, []byte, error) {
	switch kind {
	case "analyze":
		return []string{s.Self, "serve-worker", "analyze"}, payload, nil
	case "decrypt":
		return []string{s.Self, "serve-worker", "decrypt"}, payload, nil
	case "demo":
		return []string{s.Self, "serve-worker", "analyze"}, DemoCapture(), nil
	case "decrypt-demo":
		return []string{s.Self, "serve-worker", "decrypt-demo"}, nil, nil
	}
	return nil, nil, fmt.Errorf("unknown worker kind")
}

// Listen binds 127.0.0.1:port (0 picks a free port) and returns the bound port.
func (s *Server) Listen(port int) (int, error) {
	l, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	s.listener = l
	s.port = l.Addr().(*net.TCPAddr).Port
	return s.port, nil
}

// Serve accepts until Close; at most MaxHandlers requests are served at once and the rest are answered 503.
func (s *Server) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				s.handle(conn)
			}()
		default:
			s.rejected.Add(1)
			body := `{"error": "Too many concurrent requests; retry shortly."}`
			_ = conn.SetWriteDeadline(time.Now().Add(socketWait))
			_, _ = conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: " +
				strconv.Itoa(len(body)) + "\r\nRetry-After: 1\r\nConnection: close\r\n\r\n" + body))
			closeConn(conn)
		}
	}
}

// Close is server_close(): stop the live run, shut the job runner down, stop accepting.
func (s *Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.Live.Stop(nil, nil)
	s.Jobs.Shutdown()
}

func closeConn(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	conn.Close()
}

func (s *Server) handle(conn net.Conn) {
	defer closeConn(conn)
	timed := timedConn{conn}
	r := &request{conn: conn, in: bufio.NewReaderSize(timed, 65536), out: bufio.NewWriterSize(timed, 65536)}
	defer r.out.Flush()
	if !r.parse() {
		return
	}
	switch r.command {
	case "GET":
		s.doGet(r)
	case "POST":
		s.doPost(r)
	default:
		r.sendError(501, "Unsupported method ("+pyRepr(r.command)+")", "")
	}
}

// respond is Handler.respond: JSON (json.dumps(allow_nan=False)) or raw bytes.
func (s *Server) respond(r *request, code int, data interface{}, kind string) {
	var body string
	switch v := data.(type) {
	case string:
		body = v
	case []byte:
		body = string(v)
	default:
		text, err := ojson.Dumps(v)
		if err != nil {
			r.version = "dropped"
			return // the reference's handler raises: the connection closes without an answer
		}
		body = text
	}
	if kind == "" {
		kind = "application/json; charset=utf-8"
	}
	r.statusLine(code, "")
	r.header("Content-Type", kind)
	r.header("Content-Length", strconv.Itoa(len(body)))
	r.header("Cache-Control", "no-store")
	r.header("X-Content-Type-Options", "nosniff")
	r.header("Referrer-Policy", "no-referrer")
	r.header("Content-Security-Policy", csp)
	r.endHeaders()
	r.out.WriteString(body)
}

func errorBody(message string) *ojson.Object { return ojson.NewObject("error", message) }

// localRequest refuses cross-origin requests and DNS-rebinding Host values.
func (s *Server) localRequest(r *request) bool {
	expected := "127.0.0.1:" + strconv.Itoa(s.port)
	if host, ok := r.get("Host"); !ok || host != expected {
		s.respond(r, 403, errorBody("Use the local 127.0.0.1 address printed by the launcher."), "")
		return false
	}
	if origin, ok := r.get("Origin"); ok && origin != "http://"+expected {
		s.respond(r, 403, errorBody("Cross-origin requests are not allowed."), "")
		return false
	}
	return true
}

var staticFiles = map[string][2]string{
	"/":           {"index.html", "text/html; charset=utf-8"},
	"/store.js":   {"store.js", "text/javascript; charset=utf-8"},
	"/live.js":    {"live.js", "text/javascript; charset=utf-8"},
	"/decrypt.js": {"decrypt.js", "text/javascript; charset=utf-8"},
	"/app.js":     {"app.js", "text/javascript; charset=utf-8"},
	"/styles.css": {"styles.css", "text/css; charset=utf-8"},
}

// queryDict is dict(part.split("=", 1) for part in query.split("&") if "=" in part).
func queryDict(query string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(query, "&") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

func (s *Server) doGet(r *request) {
	if !s.localRequest(r) {
		return
	}
	path, query, ok := urlsplit(r.path)
	if !ok {
		return // urlsplit raised: no answer
	}
	switch {
	case path == "/api/live/interfaces":
		s.respond(r, 200, s.Live.Interfaces(), "")
	case path == "/api/live/status":
		s.respond(r, 200, s.Live.Snapshot(), "")
	case path == "/api/live/state":
		s.respond(r, 200, s.Live.StateView(), "")
	case path == "/api/live/events":
		q := queryDict(query)
		cursorText, limitText := "0", "500"
		if v, ok := q["cursor"]; ok {
			cursorText = v
		}
		if v, ok := q["limit"]; ok {
			limitText = v
		}
		cursor, e1 := pyInt(cursorText)
		limit, e2 := pyInt(limitText)
		bad := func() {
			s.respond(r, 400, errorBody("cursor and limit must be non-negative integers within bounds"), "")
		}
		if e1 != "" || e2 != "" {
			bad()
			return
		}
		page, err := s.Live.EventsSinceBig(cursor, limit)
		if err != nil {
			bad()
			return
		}
		s.respond(r, 200, page, "")
	case strings.HasPrefix(path, "/api/jobs/"):
		if job := s.Jobs.Get(path[len("/api/jobs/"):], true); job != nil {
			s.respond(r, 200, job, "")
		} else {
			s.respond(r, 404, errorBody("Unknown or expired job."), "")
		}
	case path == "/api/health":
		health, err := s.health()
		if err != nil {
			r.version = "dropped"
			return
		}
		s.respond(r, 200, health, "")
	case path == "/api/server":
		s.respond(r, 200, ojson.NewObject("jobs", s.Jobs.Status(), "handlers", ojson.FromInt(MaxHandlers),
			"rejected_requests", ojson.FromInt(s.rejected.Load()), "live", s.liveState()), "")
	case path == "/api/catalog":
		body, err := s.catalogBody()
		if err != nil {
			r.version = "dropped" // catalog_data() raises in the reference (no SOURCE.json): no answer
			return
		}
		s.respond(r, 200, body, "")
	case path == "/api/sample":
		s.respond(r, 200, DemoCapture(), "application/vnd.tcpdump.pcap")
	default:
		file, ok := staticFiles[path]
		if !ok {
			s.respond(r, 404, errorBody("Not found"), "")
			return
		}
		data, err := os.ReadFile(filepath.Join(s.Root, "web", file[0]))
		if err != nil {
			return // read_bytes raised: no answer
		}
		s.respond(r, 200, data, file[1])
	}
}

func (s *Server) liveState() ojson.Value {
	v, _ := s.Live.Snapshot().Get("state")
	return v
}

func (s *Server) catalogBody() (string, error) {
	s.catalog.Lock()
	defer s.catalog.Unlock()
	if s.catalog.body != "" {
		return s.catalog.body, nil // the catalog is fixed for the life of the process
	}
	value, err := catalog(s.Root)
	if err != nil {
		return "", err
	}
	body, err := ojson.Dumps(value)
	if err != nil {
		return "", err
	}
	s.catalog.body = body
	return s.catalog.body, nil
}

func (s *Server) health() (*ojson.Object, error) {
	s.instance.Lock()
	if s.instance.id == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		s.instance.id, s.instance.started = hex.EncodeToString(b), time.Now()
	}
	id, started := s.instance.id, s.instance.started
	s.instance.Unlock()
	data, err := os.ReadFile(filepath.Join(s.Root, "SOURCE.json"))
	if err != nil {
		return nil, err
	}
	v, err := ojson.Decode(data)
	if err != nil {
		return nil, err
	}
	source, _ := v.(*ojson.Object)
	field := func(k string) ojson.Value { x, _ := source.Get(k); return x }
	limits := ojson.NewObject("upload_mb", ojson.FromInt(8), "frames", ojson.FromInt(MaxFrames), "sessions", ojson.FromInt(MaxSessions),
		"worker_seconds", ojson.FromInt(WorkerSeconds))
	// "python" is the interpreter version in the reference; this service runs no interpreter of its own.
	return ojson.NewObject("build_digest", field("build_digest"), "version", field("version"), "commit", field("commit"),
		"components", field("components"), "python", nil, "instance", id,
		"uptime_seconds", pyjson.Round(time.Since(started).Seconds(), 1), "jobs", s.Jobs.Status(), "live", s.liveState(),
		"handlers", ojson.FromInt(MaxHandlers), "limits", limits), nil
}

// contentLength is int(self.headers.get("Content-Length", "0")).
func contentLength(r *request) (*big.Int, string) {
	text, ok := r.get("Content-Length")
	if !ok {
		text = "0"
	}
	return pyInt(text)
}

func within(n *big.Int, lo, hi int64) bool {
	return n.Cmp(big.NewInt(lo)) >= 0 && n.Cmp(big.NewInt(hi)) <= 0
}

func chunked(r *request) bool { v, ok := r.get("Transfer-Encoding"); return ok && v != "" }

// readBody is rfile.read(length): the error is the text the handler answers 400 with.
func readBody(r *request, length int64) ([]byte, string) {
	data := make([]byte, 0, min64(length, 1<<20))
	buf := make([]byte, 65536)
	for int64(len(data)) < length {
		want := length - int64(len(data))
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, err := r.in.Read(buf[:want])
		data = append(data, buf[:n]...)
		if err != nil {
			if isTimeout(err) {
				return nil, "timed out"
			}
			break
		}
	}
	if int64(len(data)) != length {
		return data, "Incomplete upload."
	}
	return data, ""
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// pySlice is s[start:end] with Python's clamping (end may be negative).
func pySlice(s string, start, end int) string {
	n := len(s)
	if end < 0 {
		end += n
	}
	if start > n {
		start = n
	}
	if end > n {
		end = n
	}
	if end < start {
		return ""
	}
	return s[start:end]
}

func (s *Server) tokenOK(r *request) bool {
	v, ok := r.get("X-Live-Token")
	return ok && v == s.Live.Token
}

func (s *Server) doPost(r *request) {
	if !s.localRequest(r) {
		return
	}
	path, query, ok := urlsplit(r.path)
	if !ok {
		return
	}
	switch {
	case path == "/api/decrypt" || path == "/api/decrypt/demo":
		if !s.tokenOK(r) {
			s.respond(r, 403, errorBody("Reload the dashboard before decryption."), "")
			return
		}
		length, msg := contentLength(r)
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		if !within(length, 0, MaxDecrypt) || chunked(r) {
			s.respond(r, 413, errorBody("Decryption upload exceeds its limit."), "")
			return
		}
		data, msg := readBody(r, length.Int64())
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		kind := "decrypt"
		if strings.HasSuffix(path, "/demo") {
			kind = "decrypt-demo"
		}
		s.runJob(r, kind, data, false)
	case strings.HasPrefix(path, "/api/jobs"):
		if !s.tokenOK(r) {
			s.respond(r, 403, errorBody("Reload the dashboard before starting a job."), "")
			return
		}
		if strings.HasSuffix(path, "/cancel") {
			if job := s.Jobs.Cancel(pySlice(path, len("/api/jobs/"), -len("/cancel"))); job != nil {
				s.respond(r, 200, job, "")
			} else {
				s.respond(r, 404, errorBody("Unknown or expired job."), "")
			}
			return
		}
		if path != "/api/jobs" {
			s.respond(r, 404, errorBody("Not found"), "")
			return
		}
		kind := ""
		if strings.HasPrefix(query, "kind=") {
			kind = strings.Replace(query, "kind=", "", 1)
		} else if v, ok := r.get("X-Job-Kind"); ok {
			kind = v
		}
		length, msg := contentLength(r)
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		limit := int64(MaxUpload)
		if strings.HasPrefix(kind, "decrypt") {
			limit = MaxDecrypt
		}
		if !within(length, 0, limit) || chunked(r) {
			s.respond(r, 413, errorBody("Upload exceeds its limit."), "")
			return
		}
		data, msg := readBody(r, length.Int64())
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		switch {
		case kind != "analyze" && kind != "demo" && kind != "decrypt" && kind != "decrypt-demo":
			s.respond(r, 400, errorBody("Unknown job kind."), "")
		case kind == "analyze" && len(data) == 0:
			s.respond(r, 400, errorBody("Choose a non-empty PCAP or PCAPNG file."), "")
		default:
			job, err := s.Jobs.Submit(kind, data)
			if err != nil {
				s.respond(r, 429, errorBody(err.Error()), "")
				return
			}
			s.respond(r, 202, job, "")
		}
	case path == "/api/live/start" || path == "/api/live/stop" || path == "/api/live/heartbeat" || path == "/api/live/reset":
		s.liveControl(r, path)
	case path == "/api/demo" || path == "/api/analyze":
		length, msg := contentLength(r)
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		if !within(length, 0, MaxUpload) {
			s.respond(r, 413, errorBody("Capture must be smaller than 8 MB."), "")
			return
		}
		if chunked(r) {
			s.respond(r, 400, errorBody("Send a file with Content-Length."), "")
			return
		}
		data, msg := readBody(r, length.Int64())
		if msg != "" {
			s.respond(r, 400, errorBody(msg), "")
			return
		}
		if path == "/api/analyze" && len(data) == 0 {
			s.respond(r, 400, errorBody("Choose a non-empty PCAP or PCAPNG file."), "")
			return
		}
		kind := "analyze"
		if path == "/api/demo" {
			kind, data = "demo", nil
		}
		s.runJob(r, kind, data, true)
	default:
		s.respond(r, 404, errorBody("Not found"), "")
	}
}

// runJob is run_job(kind, payload): submit, wait for the outcome, answer it (the synchronous endpoints).
func (s *Server) runJob(r *request, kind string, payload []byte, analysis bool) {
	job, err := s.Jobs.Submit(kind, payload)
	if err != nil {
		s.respond(r, 429, errorBody(err.Error()), "")
		return
	}
	id, _ := job.Get("id")
	exceeded := fmt.Sprintf("Analysis exceeded %d seconds. Use a smaller capture.", WorkerSeconds)
	done := s.Jobs.Wait(id.(string), WorkerSeconds+2)
	state := ""
	if done != nil {
		v, _ := done.Get("state")
		state, _ = v.(string)
	}
	if done == nil || state == "queued" || state == "running" {
		s.Jobs.Cancel(id.(string))
		s.respond(r, 400, errorBody(exceeded), "")
		return
	}
	if state != "done" {
		if state == "expired" {
			s.respond(r, 400, errorBody(exceeded), "")
			return
		}
		reasonValue, _ := done.Get("reason")
		reason, _ := reasonValue.(string)
		message := "Decryption worker failed; no decrypted result published."
		if kind == "analyze" || kind == "demo" {
			message = "The analysis worker could not finish this capture."
		}
		if state == "failed" && reason != "" && !strings.HasPrefix(reason, "worker") {
			message = reason
		}
		s.respond(r, 400, errorBody(message), "")
		return
	}
	result, _ := done.Get("result")
	if analysis {
		meta, ok1 := result.(*ojson.Object)
		var m *ojson.Object
		if ok1 {
			mv, _ := meta.Get("meta")
			m, ok1 = mv.(*ojson.Object)
		}
		if !ok1 {
			r.version = "dropped" // result["meta"]["synthetic"] raises in the reference: no answer
			return
		}
		m.Set("synthetic", kind == "demo")
	}
	s.respond(r, 200, result, "")
}

func (s *Server) liveControl(r *request, path string) {
	if !s.tokenOK(r) {
		s.respond(r, 403, errorBody("Reload the dashboard before starting capture."), "")
		return
	}
	length, msg := contentLength(r)
	if msg != "" {
		s.respond(r, 400, errorBody(msg), "")
		return
	}
	if !within(length, 0, 1024) || chunked(r) {
		s.respond(r, 400, errorBody("Invalid live control request."), "")
		return
	}
	data, msg := readBody(r, length.Int64())
	if msg == "timed out" {
		s.respond(r, 400, errorBody(msg), "")
		return
	}
	// The reference parses what arrived: this path has no incomplete-upload check.
	options := ojson.NewObject()
	if len(data) > 0 {
		v, err := ojson.Decode(data)
		if err != nil {
			if se, ok := err.(*ojson.SyntaxError); ok && se.Kind == "recursion" {
				return // RecursionError is not caught by the reference's handler
			}
			s.respond(r, 400, errorBody(err.Error()), "")
			return
		}
		o, ok := v.(*ojson.Object)
		if !ok {
			s.respond(r, 400, errorBody("Invalid live options."), "")
			return
		}
		options = o
	}
	get := func(k string, fallback ojson.Value) ojson.Value {
		if v, ok := options.Get(k); ok {
			return v
		}
		return fallback
	}
	switch {
	case strings.HasSuffix(path, "/start"):
		result, err := s.Live.Start(get("interface", nil), get("duration", ojson.FromInt(120)), get("scope", "all"), get("keylog_path", nil))
		if err != nil {
			s.respond(r, 400, errorBody(err.Error()), "")
			return
		}
		s.respond(r, 200, result, "")
	case strings.HasSuffix(path, "/heartbeat"):
		renewed := s.Live.Heartbeat(get("run_id", nil))
		result := s.Live.Snapshot()
		result.Set("renewed", renewed)
		s.respond(r, 200, result, "")
	case strings.HasSuffix(path, "/reset"):
		outcome := s.Live.Reset(get("run_id", nil))
		s.respond(r, 200, livectl.Merge(s.Live.StateView(), outcome), "")
	default:
		s.Live.Stop(nil, get("run_id", nil))
		s.respond(r, 200, s.Live.Snapshot(), "")
	}
}
