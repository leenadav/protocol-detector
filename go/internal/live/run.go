package live

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

// RunConfig are run_capture's arguments.
type RunConfig struct {
	Options
	Duration      float64 // seconds, including idle time; 0: until interrupted or end of input
	MaxPackets    int     // 0: unlimited
	StatsInterval float64 // seconds between progress summaries; 0 disables
	// ReplayClock takes the clock from the capture: the timestamp of the record being accepted. A replay of a
	// recorded stream is then a function of its bytes alone (tests and offline replays).
	ReplayClock bool
	CaptureID   string // "" draws a random capture id
}

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// CaptureCommand is capture_command: the tcpdump argv for an interface and a filter. argv only: neither is
// ever evaluated by a shell.
func CaptureCommand(iface, bpf string) ([]string, error) {
	if iface == "" || strings.HasPrefix(iface, "-") || len(iface) > 128 || !interfaceName.MatchString(iface) {
		return nil, &Error{"Invalid interface name"}
	}
	if bpf == "" || len([]rune(bpf)) > 4096 || strings.ContainsRune(bpf, 0) {
		return nil, &Error{"Capture filter must contain 1..4096 characters"}
	}
	executable, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, &Error{"tcpdump not found; install it or use --stdin"}
	}
	return []string{executable, "-n", "-p", "-U", "--immediate-mode", "-s", "262144", "-i", iface, "-w", "-", "--", "ip and (" + bpf + ")"}, nil
}

var statLine = regexp.MustCompile(`^\s*(\d+) packets? (captured|received by filter|dropped by kernel|dropped by interface)\s*$`)

// diagnostics bounds both the stderr backlog and the retained diagnostic text (CaptureDiagnostics).
type diagnostics struct {
	pending, tail []byte
	stats         map[string]int
	order         []string
}

func (d *diagnostics) feed(data []byte) {
	d.tail = append(d.tail, data...)
	if len(d.tail) > 4096 {
		d.tail = d.tail[len(d.tail)-4096:]
	}
	d.pending = append(d.pending, data...)
	for {
		index := -1
		for i, b := range d.pending {
			if b == '\n' {
				index = i
				break
			}
		}
		if index < 0 {
			break
		}
		d.line(d.pending[:index])
		d.pending = append([]byte{}, d.pending[index+1:]...)
	}
	if len(d.pending) > 8192 {
		d.pending = d.pending[len(d.pending)-8192:]
	}
}

func (d *diagnostics) line(line []byte) {
	match := statLine.FindSubmatch(line)
	if match == nil {
		return
	}
	n, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return
	}
	key := strings.ReplaceAll(string(match[2]), " ", "_")
	if _, seen := d.stats[key]; !seen {
		d.order = append(d.order, key)
	}
	d.stats[key] = n
}

type chunk struct {
	label string
	data  []byte
	end   bool
}

func pump(r io.Reader, label string, out chan<- chunk, quit <-chan struct{}) {
	for {
		buffer := make([]byte, 65536)
		n, err := r.Read(buffer)
		if n > 0 {
			select {
			case out <- chunk{label: label, data: buffer[:n]}:
			case <-quit:
				return
			}
		}
		if err != nil {
			select {
			case out <- chunk{label: label, end: true}:
			case <-quit:
			}
			return
		}
	}
}

// Run is run_capture: inspect the pcap stream (tcpdump's standard output, or a replayed stream when process is
// nil) until the duration, the packet limit, an interrupt or the end of input, then publish the final summary.
// It returns the exit status: 0, 1 after an error, 2 when loss or truncation was reported.
func Run(stream io.Reader, process *exec.Cmd, stderr io.Reader, pack *content.Pack, cfg RunConfig, emit func(Event)) (int, error) {
	monitor, err := NewMonitor(pack, cfg.Options, cfg.CaptureID, emit)
	if err != nil {
		return 1, err
	}
	began := time.Now()
	replayNow := 0.0
	clock := func() float64 {
		if cfg.ReplayClock {
			return replayNow
		}
		return time.Since(began).Seconds() + 1 // monotonic; never the reference's "no timestamp yet" zero
	}
	decoder := capture.NewDecoder()
	diag := &diagnostics{stats: map[string]int{}}
	chunks, quit := make(chan chunk), make(chan struct{})
	defer close(quit)
	open := 1
	go pump(stream, "data", chunks, quit)
	if process != nil && stderr != nil {
		open++
		go pump(stderr, "stderr", chunks, quit)
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)

	start := clock()
	nextStats := start + cfg.StatsInterval
	stopped, naturalEOF := false, false
	failure := ""
	for !stopped && !naturalEOF && failure == "" {
		now := clock()
		if cfg.Duration > 0 && now-start >= cfg.Duration {
			stopped = true
			break
		}
		if cfg.MaxPackets > 0 && monitor.Packets() >= cfg.MaxPackets {
			stopped = true
			break
		}
		_ = monitor.Tick(now)
		if cfg.StatsInterval > 0 && now >= nextStats {
			emit(monitor.Summary(now-start, false, nil, nil))
			nextStats = now + cfg.StatsInterval
		}
		var timeout <-chan time.Time
		if !cfg.ReplayClock {
			wait := 0.25
			if cfg.Duration > 0 {
				if left := cfg.Duration - (now - start); left < wait {
					wait = left
				}
				if wait < 0 {
					wait = 0
				}
			}
			timeout = time.After(time.Duration(wait * float64(time.Second)))
		}
		select {
		case <-interrupts:
			stopped = true
		case <-timeout:
		case c := <-chunks:
			switch {
			case c.end:
				open--
				if c.label == "data" {
					naturalEOF = true
				}
			case c.label == "stderr":
				diag.feed(c.data)
			default:
				records, ferr := decoder.Feed(c.data)
				if ferr != nil {
					failure = ferr.Error()
					break
				}
				for _, record := range records {
					if cfg.ReplayClock {
						replayNow = record.Timestamp
					}
					_ = monitor.Accept(record, clock())
					if cfg.MaxPackets > 0 && monitor.Packets() >= cfg.MaxPackets {
						stopped = true
						break
					}
				}
			}
		}
	}
	if naturalEOF && failure == "" {
		if eerr := decoder.End(); eerr != nil {
			failure = eerr.Error()
		}
	}
	// Terminate capture and drain both pipes together, so a full output pipe cannot prevent tcpdump from
	// exiting or printing its final loss counters.
	if process != nil {
		if process.ProcessState == nil {
			_ = process.Process.Signal(os.Interrupt)
		}
		deadline := time.After(2 * time.Second)
	drain:
		for open > 0 {
			select {
			case c := <-chunks:
				switch {
				case c.end:
					open--
				case c.label == "stderr":
					diag.feed(c.data)
				default:
					monitor.AddCount("unprocessed_pipe_bytes_at_stop", len(c.data))
				}
			case <-deadline:
				break drain
			}
		}
		exited := make(chan error, 1)
		go func() { exited <- process.Wait() }()
		var werr error
		select {
		case werr = <-exited:
		case <-time.After(2 * time.Second):
			_ = process.Process.Kill()
			werr = <-exited
		}
		diag.line(diag.pending)
		if status, bad := exitStatus(werr); bad {
			failure = "tcpdump exited with status " + strconv.Itoa(status) + ": " + strings.TrimSpace(strings.ToValidUTF8(string(diag.tail), "�"))
		}
	} else {
		diag.line(diag.pending)
	}
	drops := diag.stats["dropped_by_kernel"] + diag.stats["dropped_by_interface"]
	if drops > 0 {
		_ = monitor.InvalidateAll("Capture reported packet loss; observations may be incomplete", "all_observations_this_capture")
	}
	if failure != "" {
		_ = monitor.InvalidateAll("Capture failed; observations may be incomplete", "all_observations_this_capture")
		emit(Event{Kind: "error", Fields: map[string]interface{}{"type": "error", "reason": failure}})
	}
	if naturalEOF {
		_ = monitor.End("Capture input EOF before initial message completed")
	} else {
		_ = monitor.End("Capture stopped before initial message completed")
	}
	summary := monitor.Summary(clock()-start, true, diag.stats, diag.order)
	_, kernel := diag.stats["dropped_by_kernel"]
	switch {
	case failure != "":
		summary.Fields["capture_quality"] = "failed"
	case drops > 0:
		summary.Fields["capture_quality"] = "loss_reported"
	case monitor.Truncated() > 0:
		summary.Fields["capture_quality"] = "truncated"
	case kernel:
		summary.Fields["capture_quality"] = "no_kernel_drops_reported"
	default:
		summary.Fields["capture_quality"] = "unverified"
	}
	switch {
	case failure != "":
		summary.Fields["stop_reason"] = "error"
	case stopped:
		summary.Fields["stop_reason"] = "limit_or_interrupt"
	default:
		summary.Fields["stop_reason"] = "eof"
	}
	emit(summary)
	switch {
	case failure != "":
		return 1, nil
	case drops > 0 || monitor.Truncated() > 0:
		return 2, nil
	}
	return 0, nil
}

// exitStatus is the process's return code as the reference reads it (negative signal number when killed by
// one) and whether it is a failure: anything but 0 or an interrupt.
func exitStatus(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 1, true
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		code := -int(status.Signal())
		return code, status.Signal() != syscall.SIGINT
	}
	return exit.ExitCode(), exit.ExitCode() != 0
}

// Diagnostics parses tcpdump's standard error: its closing statistics, and a bounded tail of the text.
type Diagnostics struct{ d diagnostics }

// NewDiagnostics returns an empty parser.
func NewDiagnostics() *Diagnostics { return &Diagnostics{diagnostics{stats: map[string]int{}}} }

// Feed takes more of the stream; End parses what is left without a line end.
func (x *Diagnostics) Feed(data []byte) { x.d.feed(data) }
func (x *Diagnostics) End()             { x.d.line(x.d.pending) }

// Stats are the statistics tcpdump printed and their order.
func (x *Diagnostics) Stats() (map[string]int, []string) { return x.d.stats, x.d.order }
