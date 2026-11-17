package serve

import (
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// limitCPU is limit_worker_cpu(resource, 22): a CPU budget that never raises an inherited hard limit. The
// reference dies of SIGXCPU at the soft limit (its default action); the Go runtime ignores that signal
// unless asked, so it is caught and re-raised with the default action to end the same way (status -24).
func limitCPU(seconds uint64) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &limit); err != nil {
		return
	}
	capped := func(v uint64) uint64 {
		if limit.Max != ^uint64(0) && v > limit.Max {
			return limit.Max
		}
		return v
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: capped(seconds), Max: capped(seconds + 1)})
	xcpu := make(chan os.Signal, 1)
	signal.Notify(xcpu, syscall.SIGXCPU)
	go func() {
		<-xcpu
		signal.Reset(syscall.SIGXCPU)
		_ = syscall.Kill(os.Getpid(), syscall.SIGXCPU)
	}()
}

func emit(stdout io.Writer, v ojson.Value) int {
	text, err := ojson.Dumps(v)
	if err != nil {
		return 1 // print(json.dumps(..., allow_nan=False)) raises: nothing is written
	}
	_, _ = io.WriteString(stdout, text+"\n")
	return 0
}

func runeTruncate(s string, n int) string {
	if utf8.ValidString(s) {
		return truncateRunes(s, n)
	}
	return s[:min(len(s), n)]
}

// AnalyzeWorker is `server.py --worker`: a capture on standard input, the analysis result (or
// {"error": ...}) on standard output.
func AnalyzeWorker(stdin io.Reader, stdout io.Writer) int {
	limitCPU(22)
	started := time.Now()
	fail := func(message string) int {
		return emit(stdout, ojson.NewObject("error", "Capture could not be analyzed: "+runeTruncate(message, 240)))
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxUpload+1))
	if err != nil {
		return fail(err.Error())
	}
	if len(data) > MaxUpload {
		return fail("Capture exceeds 8 MB.")
	}
	pack, err := content.Embedded()
	if err != nil {
		return fail("The Go backend failed (status 1).")
	}
	limits := analyze.Limits{Frames: MaxFrames, Sessions: MaxSessions, Events: MaxEvents}
	text, err := analyze.Present(data, pack, limits, func() float64 { return float64(time.Since(started).Nanoseconds()) / 1e6 })
	if err != nil {
		if refused, ok := err.(*analyze.PresentError); ok {
			return fail(refused.Message)
		}
		return fail("The Go backend failed (status 1).")
	}
	_, _ = io.WriteString(stdout, text+"\n")
	return 0
}

// DecryptWorker is `server.py --decrypt-worker`: {"capture": base64, "keylog": text} on standard input, the
// decryption report with "synthetic": false (or {"error": ...}) on standard output. Secrets arrive on
// standard input only and are never written.
func DecryptWorker(stdin io.Reader, stdout io.Writer) int {
	limitCPU(22)
	fail := func(message string) int { return emit(stdout, ojson.NewObject("error", runeTruncate(message, 240))) }
	invalid := func() int { return emit(stdout, ojson.NewObject("error", "Invalid decryption request.")) }
	data, err := io.ReadAll(io.LimitReader(stdin, MaxDecrypt+1))
	if err != nil {
		return fail(err.Error())
	}
	v, err := ojson.Decode(data)
	if err != nil {
		if se, ok := err.(*ojson.SyntaxError); ok && se.Kind == "json" {
			return invalid() // JSONDecodeError
		}
		return fail(err.Error()) // UnicodeDecodeError and the other ValueErrors reach `except Exception`
	}
	request, ok := v.(*ojson.Object)
	if !ok {
		return invalid() // request['capture'] on a list, a string or a number is a TypeError
	}
	captureValue, ok := request.Get("capture")
	if !ok {
		return invalid()
	}
	captureText, ok := captureValue.(string)
	if !ok {
		return invalid() // b64decode of anything but text is a TypeError
	}
	capture, msg := b64decodeStrict(captureText)
	if msg != "" {
		return fail(msg)
	}
	keylogValue, ok := request.Get("keylog")
	if !ok {
		return invalid()
	}
	if len(capture) > keylogcap.MaxCapture {
		return fail("Capture exceeds 8 MiB.")
	}
	keylog, ok := keylogValue.(string)
	if !ok {
		return fail("Key log must be text.")
	}
	pack, err := content.Embedded()
	if err != nil {
		return fail("The Go backend failed (status 1).")
	}
	text, err := keylogcap.Analyze(capture, keylog, pack)
	if err != nil {
		if refused, ok := err.(*keylogcap.Refusal); ok {
			return fail(refused.Message)
		}
		if strings.Contains(err.Error(), "not ported") {
			return fail("The Go backend failed (status 64).")
		}
		return fail("The Go backend failed (status 1).")
	}
	report, err := ojson.Decode([]byte(text))
	if err != nil {
		return fail("The Go backend failed (status 0).")
	}
	if o, ok := report.(*ojson.Object); ok {
		o.Set("synthetic", false)
	}
	return emit(stdout, report)
}
